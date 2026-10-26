// SysmonCollector: reads Microsoft-Windows-Sysmon/Operational through the Windows Event Log API.
// It subscribes to future events only (no bookmark), renders each record as XML and hands it
// to the portable mapper. It never writes to the event log or changes Sysmon's configuration.
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winevt.h>

#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "edr/sysmon.hpp"
#include "edr/windows.hpp"
#include "edr/xml.hpp"

namespace edr::windows {
namespace {

constexpr const wchar_t* kChannel = L"Microsoft-Windows-Sysmon/Operational";
constexpr DWORD kBatch = 16;

class SysmonCollector final : public ICollector {
 public:
  SysmonCollector(std::string host, Logger& log) : log_(log) {
    options_.host_override = std::move(host);
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  }
  SysmonCollector(const SysmonCollector&) = delete;
  SysmonCollector& operator=(const SysmonCollector&) = delete;
  SysmonCollector(SysmonCollector&&) = delete;
  SysmonCollector& operator=(SysmonCollector&&) = delete;
  ~SysmonCollector() override {
    if (stop_event_ != nullptr) {
      CloseHandle(stop_event_);
    }
  }

  [[nodiscard]] std::string_view name() const override { return "sysmon"; }

  void stop() override {
    if (stop_event_ != nullptr) {
      SetEvent(stop_event_);
    }
  }

  bool run(const EventCallback& on_event) override {
    if (stop_event_ == nullptr) {
      log_.error("CreateEvent failed", {{"error", std::to_string(GetLastError())}});
      return false;
    }
    HANDLE signal = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (signal == nullptr) {
      log_.error("CreateEvent failed", {{"error", std::to_string(GetLastError())}});
      return false;
    }
    EVT_HANDLE sub = EvtSubscribe(nullptr, signal, kChannel, L"*", nullptr, nullptr, nullptr,
                                  EvtSubscribeToFutureEvents);
    if (sub == nullptr) {
      const DWORD err = GetLastError();
      if (err == ERROR_EVT_CHANNEL_NOT_FOUND) {
        log_.error("Sysmon event channel not found: install Sysmon first (see README)");
      } else if (err == ERROR_ACCESS_DENIED) {
        log_.error(
            "access denied to the Sysmon channel: run as Administrator or a member of "
            "Event Log Readers");
      } else {
        log_.error("EvtSubscribe failed", {{"error", std::to_string(err)}});
      }
      CloseHandle(signal);
      return false;
    }
    log_.info("subscribed to Sysmon channel");
    HANDLE waits[2] = {stop_event_, signal};
    bool ok = true;
    while (true) {
      const DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
      if (w == WAIT_OBJECT_0) {
        break;
      }
      if (w != WAIT_OBJECT_0 + 1) {
        log_.error("WaitForMultipleObjects failed", {{"error", std::to_string(GetLastError())}});
        ok = false;
        break;
      }
      drain(sub, on_event);
    }
    EvtClose(sub);
    CloseHandle(signal);
    return ok;
  }

 private:
  void drain(EVT_HANDLE sub, const EventCallback& on_event) {
    while (true) {
      EVT_HANDLE events[kBatch] = {};
      DWORD returned = 0;
      if (EvtNext(sub, kBatch, events, 1000, 0, &returned) == FALSE) {
        const DWORD err = GetLastError();
        if (err != ERROR_NO_MORE_ITEMS && err != ERROR_TIMEOUT) {
          log_.warn("EvtNext failed", {{"error", std::to_string(err)}});
        }
        return;
      }
      for (DWORD i = 0; i < returned; ++i) {
        handle(events[i], on_event);
        EvtClose(events[i]);
      }
    }
  }

  void handle(EVT_HANDLE record, const EventCallback& on_event) {
    DWORD used = 0;
    DWORD props = 0;
    if (EvtRender(nullptr, record, EvtRenderEventXml,
                  static_cast<DWORD>(buffer_.size() * sizeof(wchar_t)), buffer_.data(), &used,
                  &props) == FALSE) {
      if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        log_.warn("EvtRender failed", {{"error", std::to_string(GetLastError())}});
        return;
      }
      buffer_.resize(used / sizeof(wchar_t) + 1);
      if (EvtRender(nullptr, record, EvtRenderEventXml,
                    static_cast<DWORD>(buffer_.size() * sizeof(wchar_t)), buffer_.data(), &used,
                    &props) == FALSE) {
        log_.warn("EvtRender failed", {{"error", std::to_string(GetLastError())}});
        return;
      }
    }
    std::size_t chars = used / sizeof(wchar_t);
    if (chars > 0 && buffer_[chars - 1] == L'\0') {
      --chars;
    }
    const std::string text = to_utf8(buffer_.data(), chars);
    auto parsed = xml::parse(text);
    if (auto* err = std::get_if<xml::ParseError>(&parsed)) {
      log_.warn("rendered event is not valid XML", {{"error", err->message}});
      return;
    }
    const xml::Element& doc = std::get<xml::Element>(parsed);
    if (doc.children.empty()) {
      return;
    }
    auto mapped = map_sysmon_event(doc.children.front(), options_);
    if (auto* ev = std::get_if<Event>(&mapped)) {
      on_event(std::move(*ev));
    } else {
      log_.debug("Sysmon record not mapped", {{"reason", std::get<MapError>(mapped).message}});
    }
  }

  Logger& log_;
  SysmonOptions options_;
  HANDLE stop_event_ = nullptr;
  std::vector<wchar_t> buffer_ = std::vector<wchar_t>(16384);
};

}  // namespace

std::unique_ptr<ICollector> make_sysmon_collector(std::string host, Logger& log) {
  return std::make_unique<SysmonCollector>(std::move(host), log);
}

}  // namespace edr::windows

#endif  // _WIN32
