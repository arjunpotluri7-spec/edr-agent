// Maps rendered Sysmon event XML (Microsoft-Windows-Sysmon/Operational) to normalized events.
// This is portable code: the Windows SysmonCollector only fetches and renders the XML, so the
// mapping is unit-tested on every OS against synthetic fixtures.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "edr/event.hpp"
#include "edr/xml.hpp"

namespace edr {

struct SysmonOptions {
  std::string host_override;  // empty: use <Computer> up to the first '.'
};

struct MapError {
  std::string message;
};

// Supported event IDs: 1, 3, 5, 7, 10, 11, 12, 13, 14, 22, 23, 26.
bool sysmon_event_supported(int event_id);

// Maps one <Event> element. Unsupported IDs and malformed records return MapError.
std::variant<Event, MapError> map_sysmon_event(const xml::Element& event,
                                               const SysmonOptions& options);

struct SysmonBatch {
  std::vector<Event> events;
  std::size_t unsupported = 0;      // valid Sysmon records with an ID we do not map
  std::vector<std::string> errors;  // malformed records (message per record)
};

// Parses a document holding <Event> elements back to back, or wrapped in one root element
// (<Events>, as produced by `wevtutil qe ... /f:xml /e:Events`).
std::variant<SysmonBatch, xml::ParseError> parse_sysmon_xml(std::string_view text,
                                                            const SysmonOptions& options);

}  // namespace edr
