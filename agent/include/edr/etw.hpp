// Portable half of the ETW collector: maps decoded ETW event properties to normalized events.
//
// The Windows-only EtwCollector (src/windows/etw_collector.cpp) runs the real-time session and
// uses TDH to decode each EVENT_RECORD into an EtwRecord; everything after that lives here so it
// is unit-tested on every OS. Event IDs and property names come from the provider manifests:
//   Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
//     1 ProcessStart (ProcessID, ParentProcessID, ImageName), 2 ProcessStop (ProcessID, ImageName)
//   Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88}
//     12 TCPv4 connection attempted, 28 TCPv6 connection attempted (PID, daddr, saddr, dport,
//     sport)
//   Microsoft-Windows-DNS-Client {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
//     3008 query completed (QueryName, QueryStatus, QueryResults)
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "edr/event.hpp"

namespace edr {

enum class EtwProvider { KernelProcess, KernelNetwork, DnsClient };

// A property value after TDH decoding: text (UTF-8), an unsigned integer, or raw bytes.
using EtwValue =
    std::variant<std::monostate, std::string, std::uint64_t, std::vector<std::uint8_t>>;

struct EtwRecord {
  EtwProvider provider = EtwProvider::KernelProcess;
  std::uint16_t event_id = 0;
  std::int64_t timestamp_filetime = 0;  // 100 ns ticks since 1601-01-01 UTC
  std::uint32_t header_process_id = 0;  // EVENT_HEADER.ProcessId
  std::vector<std::pair<std::string, EtwValue>> properties;

  [[nodiscard]] const EtwValue* find(std::string_view name) const;
};

struct EtwMapContext {
  std::string host;
  // NT device prefixes to drive letters, e.g. {"\\Device\\HarddiskVolume3", "C:"}.
  std::vector<std::pair<std::string, std::string>> device_map;
  std::uint64_t sequence = 0;  // incremented per mapped event, used in event ids
};

std::int64_t filetime_to_unix_ms(std::int64_t filetime);
// "\Device\HarddiskVolume3\Windows\x.exe" -> "C:\Windows\x.exe" using the device map.
std::string nt_path_to_dos(std::string_view path,
                           const std::vector<std::pair<std::string, std::string>>& device_map);
// Kernel-Network stores IPv4 addresses and ports in network byte order inside little-endian
// integers; these undo that.
std::string ipv4_from_network_u32(std::uint32_t value);
std::uint16_t port_from_network_u16(std::uint16_t value);
std::string ipv6_to_string(const std::vector<std::uint8_t>& bytes);

// Returns nullopt for events we do not map (other IDs) or records missing required fields.
std::optional<Event> map_etw_record(const EtwRecord& r, EtwMapContext& ctx);

}  // namespace edr
