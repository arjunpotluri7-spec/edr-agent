// The normalized telemetry event every collector produces and the engine consumes.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "edr/json.hpp"

namespace edr {

enum class EventType {
  ProcessCreate,
  ProcessTerminate,
  ImageLoad,
  ProcessAccess,
  FileCreate,
  FileDelete,
  FileRename,
  RegistryCreate,
  RegistrySet,
  RegistryDelete,
  RegistryRename,
  NetworkConnect,
  DnsQuery,
};

std::string_view to_string(EventType type);
std::optional<EventType> parse_event_type(std::string_view text);
const std::vector<std::string_view>& all_event_type_names();

struct Event {
  // Identity and time
  std::string id;  // unique per event, e.g. "sysmon-WS-ALICE-01-1006"
  std::int64_t ts_ms = 0;
  std::string host;
  std::string source;  // "sysmon", "etw" or "replay"
  EventType type = EventType::ProcessCreate;
  std::optional<std::int64_t> sysmon_event_id;
  std::optional<std::int64_t> record_id;

  // Acting process
  std::int64_t pid = 0;
  std::optional<std::int64_t> ppid;
  std::string image;
  std::string command_line;
  std::string user;
  std::string integrity_level;
  std::string hashes;  // as provided by Sysmon, e.g. "SHA256=..."
  std::string process_guid;
  std::string parent_process_guid;
  std::string parent_image;
  std::string parent_command_line;

  // File / registry / process access targets
  std::string target_path;  // file path or registry key/value path
  std::string new_path;     // rename destination
  std::string details;      // registry value data
  std::string registry_event_type;
  std::string target_image;
  std::string granted_access;
  std::string image_loaded;
  std::string signed_flag;
  std::string signature;

  // Network / DNS
  std::string protocol;
  std::optional<bool> initiated;
  std::string src_ip;
  std::optional<std::int64_t> src_port;
  std::string dest_ip;
  std::optional<std::int64_t> dest_port;
  std::string dest_hostname;
  std::string query_name;
  std::string query_status;
  std::string query_results;

  // Enrichment added by the engine (not produced by collectors)
  std::string image_name;
  std::string parent_image_name;
  std::vector<std::string> ancestor_images;
  std::string decoded_command;
  std::string encoded_command_error;
};

// Field values as rules see them: absent, a single string, or a list (ancestor_images).
using FieldValue = std::variant<std::monostate, std::string, std::vector<std::string>>;

// Looks up a rule field by name (the names in docs/rules.md). Empty strings count as absent.
FieldValue get_field(const Event& event, std::string_view name);
// True if name is a field rules may reference.
bool is_known_field(std::string_view name);

struct EventParseError {
  std::string message;
};

// Validates and converts one JSON event (the replay / wire format). Unknown keys are ignored.
std::variant<Event, EventParseError> event_from_json(const json::Value& value);
// Serializes the collector fields plus decoded_command / encoded_command_error (when set) and
// parent_image. Empty strings and unset optionals are omitted.
json::Value event_to_json(const Event& event);

}  // namespace edr
