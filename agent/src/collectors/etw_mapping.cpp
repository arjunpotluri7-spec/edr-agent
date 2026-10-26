#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "edr/etw.hpp"
#include "edr/textutil.hpp"

namespace edr {
namespace {

std::optional<std::uint64_t> as_uint(const EtwRecord& r, std::string_view name) {
  const EtwValue* v = r.find(name);
  if (v == nullptr) {
    return std::nullopt;
  }
  if (const auto* u = std::get_if<std::uint64_t>(v)) {
    return *u;
  }
  return std::nullopt;
}

std::string as_text(const EtwRecord& r, std::string_view name) {
  const EtwValue* v = r.find(name);
  if (v == nullptr) {
    return {};
  }
  if (const auto* s = std::get_if<std::string>(v)) {
    return *s;
  }
  return {};
}

}  // namespace

const EtwValue* EtwRecord::find(std::string_view name) const {
  for (const auto& [k, v] : properties) {
    if (k == name) {
      return &v;
    }
  }
  return nullptr;
}

std::int64_t filetime_to_unix_ms(std::int64_t filetime) {
  constexpr std::int64_t kEpochDiff = 116444736000000000LL;  // 1601 -> 1970 in 100 ns ticks
  return (filetime - kEpochDiff) / 10000;
}

std::string nt_path_to_dos(std::string_view path,
                           const std::vector<std::pair<std::string, std::string>>& device_map) {
  for (const auto& [device, drive] : device_map) {
    if (path.size() > device.size() &&
        ascii_lower(path.substr(0, device.size())) == ascii_lower(device) &&
        path[device.size()] == '\\') {
      return drive + std::string(path.substr(device.size()));
    }
  }
  return std::string(path);
}

std::string ipv4_from_network_u32(std::uint32_t value) {
  return std::to_string(value & 0xFFU) + "." + std::to_string((value >> 8U) & 0xFFU) + "." +
         std::to_string((value >> 16U) & 0xFFU) + "." + std::to_string((value >> 24U) & 0xFFU);
}

std::uint16_t port_from_network_u16(std::uint16_t value) {
  const auto v = static_cast<unsigned>(value);
  return static_cast<std::uint16_t>(((v & 0xFFU) << 8U) | (v >> 8U));
}

std::string ipv6_to_string(const std::vector<std::uint8_t>& bytes) {
  if (bytes.size() != 16) {
    return {};
  }
  std::array<std::uint16_t, 8> groups{};
  for (std::size_t i = 0; i < groups.size(); ++i) {
    groups.at(i) = static_cast<std::uint16_t>((static_cast<unsigned>(bytes.at(2 * i)) << 8U) |
                                              static_cast<unsigned>(bytes.at(2 * i + 1)));
  }
  // RFC 5952: compress the longest run (length >= 2) of zero groups, first on ties.
  std::size_t best_start = groups.size();
  std::size_t best_len = 0;
  for (std::size_t i = 0; i < groups.size();) {
    if (groups.at(i) != 0) {
      ++i;
      continue;
    }
    std::size_t j = i;
    while (j < groups.size() && groups.at(j) == 0) {
      ++j;
    }
    if (j - i > best_len && j - i >= 2) {
      best_start = i;
      best_len = j - i;
    }
    i = j;
  }
  std::string out;
  for (std::size_t i = 0; i < groups.size(); ++i) {
    if (i == best_start) {
      out += "::";
      i += best_len - 1;
      continue;
    }
    if (!out.empty() && out.back() != ':') {
      out += ':';
    }
    out += to_hex(groups.at(i), 1);
  }
  return out;
}

std::optional<Event> map_etw_record(const EtwRecord& r, EtwMapContext& ctx) {
  Event ev;
  ev.source = "etw";
  ev.host = ctx.host;
  ev.ts_ms = filetime_to_unix_ms(r.timestamp_filetime);
  switch (r.provider) {
    case EtwProvider::KernelProcess: {
      if (r.event_id != 1 && r.event_id != 2) {
        return std::nullopt;
      }
      const auto pid = as_uint(r, "ProcessID");
      if (!pid) {
        return std::nullopt;
      }
      ev.pid = static_cast<std::int64_t>(*pid);
      ev.image = nt_path_to_dos(as_text(r, "ImageName"), ctx.device_map);
      if (r.event_id == 1) {
        ev.type = EventType::ProcessCreate;
        if (const auto ppid = as_uint(r, "ParentProcessID")) {
          ev.ppid = static_cast<std::int64_t>(*ppid);
        }
      } else {
        ev.type = EventType::ProcessTerminate;
      }
      break;
    }
    case EtwProvider::KernelNetwork: {
      if (r.event_id != 12 && r.event_id != 28) {
        return std::nullopt;
      }
      const auto pid = as_uint(r, "PID");
      const EtwValue* daddr = r.find("daddr");
      const auto dport = as_uint(r, "dport");
      if (!pid || daddr == nullptr || !dport) {
        return std::nullopt;
      }
      ev.type = EventType::NetworkConnect;
      ev.pid = static_cast<std::int64_t>(*pid);
      ev.protocol = "tcp";
      ev.initiated = true;
      auto addr = [&](const EtwValue* v) -> std::string {
        if (v == nullptr) {
          return {};
        }
        if (const auto* u = std::get_if<std::uint64_t>(v)) {
          return ipv4_from_network_u32(static_cast<std::uint32_t>(*u));
        }
        if (const auto* b = std::get_if<std::vector<std::uint8_t>>(v)) {
          return ipv6_to_string(*b);
        }
        return {};
      };
      ev.dest_ip = addr(daddr);
      ev.src_ip = addr(r.find("saddr"));
      ev.dest_port = port_from_network_u16(static_cast<std::uint16_t>(*dport));
      if (const auto sport = as_uint(r, "sport")) {
        ev.src_port = port_from_network_u16(static_cast<std::uint16_t>(*sport));
      }
      if (ev.dest_ip.empty()) {
        return std::nullopt;
      }
      break;
    }
    case EtwProvider::DnsClient: {
      if (r.event_id != 3008) {
        return std::nullopt;
      }
      ev.type = EventType::DnsQuery;
      ev.pid = r.header_process_id;
      ev.query_name = as_text(r, "QueryName");
      if (const auto status = as_uint(r, "QueryStatus")) {
        ev.query_status = std::to_string(*status);
      }
      ev.query_results = as_text(r, "QueryResults");
      if (ev.query_name.empty()) {
        return std::nullopt;
      }
      break;
    }
  }
  ++ctx.sequence;
  ev.id = "etw-" + ctx.host + "-" + std::to_string(ev.ts_ms) + "-" + std::to_string(ctx.sequence);
  return ev;
}

}  // namespace edr
