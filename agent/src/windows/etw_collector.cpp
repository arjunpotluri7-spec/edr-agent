// EtwCollector: a real-time ETW consumer for process, network and DNS telemetry.
//
// Flow: StartTraceW creates a private real-time session named "EDRAgent-Telemetry",
// EnableTraceEx2 enables each provider on it, OpenTraceW + ProcessTrace deliver EVENT_RECORDs to
// on_record() on this collector's thread, TDH decodes the top-level properties into an EtwRecord,
// and the portable map_etw_record() turns that into a normalized Event. stop() stops the session
// with ControlTraceW, which makes ProcessTrace return.
//
// Requirements: Administrator (or Performance Log Users) to start a session. If a session with
// the same name already exists (for example after a crash), the collector reports it and does
// not touch it; stop it yourself with `logman stop EDRAgent-Telemetry -ets`.
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// clang-format off
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
// clang-format on

#include <atomic>
#include <climits>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "edr/etw.hpp"
#include "edr/windows.hpp"

namespace edr::windows {
namespace {

constexpr const wchar_t* kSessionName = L"EDRAgent-Telemetry";

// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
constexpr GUID kKernelProcess = {
    0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
// {7DD42A49-5329-4832-8DFD-43D979153A88}
constexpr GUID kKernelNetwork = {
    0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};
// {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
constexpr GUID kDnsClient = {
    0x1c95126e, 0x7eea, 0x49a9, {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};

constexpr ULONGLONG kKeywordProcess = 0x10;          // WINEVENT_KEYWORD_PROCESS
constexpr ULONGLONG kKeywordIpv4Ipv6 = 0x10 | 0x20;  // KERNEL_NETWORK_KEYWORD_IPV4 | _IPV6
constexpr ULONGLONG kKeywordAll = ~0ULL;             // DNS-Client: filter by event id instead

// TDH property input types (winmeta.xml InType values). Defined here because MinGW's tdh.h does
// not declare the _TDH_IN_TYPE enum; with the Windows SDK they are checked against it below.
enum InType : USHORT {
  kUnicodeString = 1,
  kAnsiString = 2,
  kInt8 = 3,
  kUInt8 = 4,
  kInt16 = 5,
  kUInt16 = 6,
  kInt32 = 7,
  kUInt32 = 8,
  kInt64 = 9,
  kUInt64 = 10,
  kBoolean = 13,
  kBinary = 14,
  kPointer = 16,
  kFileTime = 17,
  kHexInt32 = 20,
  kHexInt64 = 21,
};
#ifdef _MSC_VER
static_assert(kUnicodeString == TDH_INTYPE_UNICODESTRING && kAnsiString == TDH_INTYPE_ANSISTRING);
static_assert(kInt8 == TDH_INTYPE_INT8 && kUInt8 == TDH_INTYPE_UINT8);
static_assert(kInt16 == TDH_INTYPE_INT16 && kUInt16 == TDH_INTYPE_UINT16);
static_assert(kInt32 == TDH_INTYPE_INT32 && kUInt32 == TDH_INTYPE_UINT32);
static_assert(kInt64 == TDH_INTYPE_INT64 && kUInt64 == TDH_INTYPE_UINT64);
static_assert(kBoolean == TDH_INTYPE_BOOLEAN && kBinary == TDH_INTYPE_BINARY);
static_assert(kPointer == TDH_INTYPE_POINTER && kFileTime == TDH_INTYPE_FILETIME);
static_assert(kHexInt32 == TDH_INTYPE_HEXINT32 && kHexInt64 == TDH_INTYPE_HEXINT64);
#endif

bool same_guid(const GUID& a, const GUID& b) {
  return std::memcmp(&a, &b, sizeof(GUID)) == 0;
}

std::uint64_t little_endian(const std::vector<std::uint8_t>& data) {
  std::uint64_t v = 0;
  const std::size_t n = data.size() < 8 ? data.size() : 8;
  for (std::size_t i = 0; i < n; ++i) {
    v |= static_cast<std::uint64_t>(data[i]) << (8U * i);
  }
  return v;
}

EtwValue decode_property(USHORT in_type, std::vector<std::uint8_t> data) {
  switch (in_type) {
    case kUnicodeString: {
      std::size_t chars = data.size() / sizeof(wchar_t);
      std::wstring w(chars, L'\0');
      std::memcpy(w.data(), data.data(), chars * sizeof(wchar_t));
      while (!w.empty() && w.back() == L'\0') {
        w.pop_back();
      }
      return to_utf8(w.data(), w.size());
    }
    case kAnsiString: {
      std::string s(data.begin(), data.end());
      while (!s.empty() && s.back() == '\0') {
        s.pop_back();
      }
      return s;
    }
    case kInt8:
    case kUInt8:
    case kInt16:
    case kUInt16:
    case kInt32:
    case kUInt32:
    case kInt64:
    case kUInt64:
    case kBoolean:
    case kPointer:
    case kFileTime:
    case kHexInt32:
    case kHexInt64:
      return little_endian(data);
    case kBinary:
      return data;
    default:
      return std::monostate{};
  }
}

std::vector<std::pair<std::string, std::string>> dos_device_map() {
  std::vector<std::pair<std::string, std::string>> map;
  wchar_t drive[3] = L"A:";
  wchar_t target[MAX_PATH] = {};
  for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
    drive[0] = letter;
    if (QueryDosDeviceW(drive, target, MAX_PATH) != 0) {
      map.emplace_back(to_utf8(target, std::wcslen(target)), to_utf8(drive, 2));
    }
  }
  return map;
}

class EtwCollector final : public ICollector {
 public:
  EtwCollector(std::string host, std::vector<std::string> providers, Logger& log)
      : providers_(std::move(providers)), log_(log) {
    ctx_.host = std::move(host);
  }
  EtwCollector(const EtwCollector&) = delete;
  EtwCollector& operator=(const EtwCollector&) = delete;
  EtwCollector(EtwCollector&&) = delete;
  EtwCollector& operator=(EtwCollector&&) = delete;
  ~EtwCollector() override { stop_session(); }

  [[nodiscard]] std::string_view name() const override { return "etw"; }

  bool run(const EventCallback& on_event) override {
    on_event_ = &on_event;
    ctx_.device_map = dos_device_map();
    if (!start_session()) {
      return false;
    }
    for (const auto& p : providers_) {
      const GUID* guid = nullptr;
      ULONGLONG keywords = 0;
      if (p == "kernel-process") {
        guid = &kKernelProcess;
        keywords = kKeywordProcess;
      } else if (p == "kernel-network") {
        guid = &kKernelNetwork;
        keywords = kKeywordIpv4Ipv6;
      } else if (p == "dns-client") {
        guid = &kDnsClient;
        keywords = kKeywordAll;
      } else {
        continue;
      }
      const ULONG st = EnableTraceEx2(session_, guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                      TRACE_LEVEL_INFORMATION, keywords, 0, 0, nullptr);
      if (st != ERROR_SUCCESS) {
        log_.error("EnableTraceEx2 failed", {{"provider", p}, {"error", std::to_string(st)}});
        stop_session();
        return false;
      }
    }

    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(kSessionName);
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = &EtwCollector::on_record;
    logfile.Context = this;
    TRACEHANDLE trace = OpenTraceW(&logfile);
    if (trace == INVALID_PROCESSTRACE_HANDLE) {
      log_.error("OpenTrace failed", {{"error", std::to_string(GetLastError())}});
      stop_session();
      return false;
    }
    log_.info("ETW session started", {{"providers", std::to_string(providers_.size())}});
    const ULONG st = ProcessTrace(&trace, 1, nullptr, nullptr);  // blocks until stopped
    CloseTrace(trace);
    stop_session();
    if (st != ERROR_SUCCESS && st != ERROR_CANCELLED) {
      log_.error("ProcessTrace failed", {{"error", std::to_string(st)}});
      return false;
    }
    return true;
  }

  void stop() override { stop_session(); }

 private:
  // EVENT_TRACE_PROPERTIES must be followed by room for the session name.
  static std::vector<std::uint8_t> make_properties() {
    const std::size_t name_bytes = (std::wcslen(kSessionName) + 1) * sizeof(wchar_t);
    std::vector<std::uint8_t> buf(sizeof(EVENT_TRACE_PROPERTIES) + name_bytes, 0);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
    props->Wnode.BufferSize = static_cast<ULONG>(buf.size());
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;  // QPC clock; real-time consumers receive FILETIME stamps
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    return buf;
  }

  bool start_session() {
    std::vector<std::uint8_t> buf = make_properties();
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
    TRACEHANDLE handle = 0;
    const ULONG st = StartTraceW(&handle, kSessionName, props);
    if (st == ERROR_ALREADY_EXISTS) {
      log_.error(
          "an ETW session named EDRAgent-Telemetry already exists; stop it with "
          "`logman stop EDRAgent-Telemetry -ets` and start the agent again");
      return false;
    }
    if (st == ERROR_ACCESS_DENIED) {
      log_.error("starting an ETW session needs Administrator rights");
      return false;
    }
    if (st != ERROR_SUCCESS) {
      log_.error("StartTrace failed", {{"error", std::to_string(st)}});
      return false;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    session_ = handle;
    running_ = true;
    return true;
  }

  void stop_session() {
    const std::lock_guard<std::mutex> lock(mutex_);
    if (!running_) {
      return;
    }
    std::vector<std::uint8_t> buf = make_properties();
    ControlTraceW(session_, nullptr, reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data()),
                  EVENT_TRACE_CONTROL_STOP);
    running_ = false;
  }

  static void WINAPI on_record(PEVENT_RECORD record) {
    auto* self = static_cast<EtwCollector*>(record->UserContext);
    if (self != nullptr) {
      self->handle(record);
    }
  }

  void handle(PEVENT_RECORD record) {
    EtwRecord r;
    const GUID& provider = record->EventHeader.ProviderId;
    if (same_guid(provider, kKernelProcess)) {
      r.provider = EtwProvider::KernelProcess;
    } else if (same_guid(provider, kKernelNetwork)) {
      r.provider = EtwProvider::KernelNetwork;
    } else if (same_guid(provider, kDnsClient)) {
      r.provider = EtwProvider::DnsClient;
    } else {
      return;
    }
    r.event_id = record->EventHeader.EventDescriptor.Id;
    // Skip early: only these IDs are mapped (see edr/etw.hpp).
    const bool wanted =
        (r.provider == EtwProvider::KernelProcess && (r.event_id == 1 || r.event_id == 2)) ||
        (r.provider == EtwProvider::KernelNetwork && (r.event_id == 12 || r.event_id == 28)) ||
        (r.provider == EtwProvider::DnsClient && r.event_id == 3008);
    if (!wanted) {
      return;
    }
    r.timestamp_filetime = record->EventHeader.TimeStamp.QuadPart;
    r.header_process_id = record->EventHeader.ProcessId;

    ULONG size = 0;
    if (TdhGetEventInformation(record, 0, nullptr, nullptr, &size) != ERROR_INSUFFICIENT_BUFFER) {
      return;
    }
    std::vector<std::uint8_t> info_buf(size);
    auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(info_buf.data());
    if (TdhGetEventInformation(record, 0, nullptr, info, &size) != ERROR_SUCCESS) {
      return;
    }
    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
      const EVENT_PROPERTY_INFO& prop = info->EventPropertyInfoArray[i];
      if ((prop.Flags & (PropertyStruct | PropertyParamCount)) != 0 || prop.count > 1) {
        continue;  // structs and arrays are not needed by the mapper
      }
      const auto* name = reinterpret_cast<const wchar_t*>(info_buf.data() + prop.NameOffset);
      PROPERTY_DATA_DESCRIPTOR desc{};
      desc.PropertyName = reinterpret_cast<ULONGLONG>(name);
      desc.ArrayIndex = ULONG_MAX;
      ULONG prop_size = 0;
      if (TdhGetPropertySize(record, 0, nullptr, 1, &desc, &prop_size) != ERROR_SUCCESS ||
          prop_size > 64 * 1024) {
        continue;
      }
      std::vector<std::uint8_t> data(prop_size);
      if (prop_size != 0 &&
          TdhGetProperty(record, 0, nullptr, 1, &desc, prop_size, data.data()) != ERROR_SUCCESS) {
        continue;
      }
      r.properties.emplace_back(to_utf8(name, std::wcslen(name)),
                                decode_property(prop.nonStructType.InType, std::move(data)));
    }
    if (auto ev = map_etw_record(r, ctx_)) {
      if (on_event_ != nullptr) {
        (*on_event_)(std::move(*ev));
      }
    }
  }

  std::vector<std::string> providers_;
  Logger& log_;
  EtwMapContext ctx_;
  const EventCallback* on_event_ = nullptr;
  std::mutex mutex_;
  TRACEHANDLE session_ = 0;
  bool running_ = false;
};

}  // namespace

std::unique_ptr<ICollector> make_etw_collector(std::string host, std::vector<std::string> providers,
                                               Logger& log) {
  return std::make_unique<EtwCollector>(std::move(host), std::move(providers), log);
}

}  // namespace edr::windows

#endif  // _WIN32
