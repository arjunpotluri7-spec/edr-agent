#include "edr/event.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "edr/textutil.hpp"

namespace edr {
namespace {

constexpr std::array<std::pair<EventType, std::string_view>, 13> kTypeNames{{
    {EventType::ProcessCreate, "process_create"},
    {EventType::ProcessTerminate, "process_terminate"},
    {EventType::ImageLoad, "image_load"},
    {EventType::ProcessAccess, "process_access"},
    {EventType::FileCreate, "file_create"},
    {EventType::FileDelete, "file_delete"},
    {EventType::FileRename, "file_rename"},
    {EventType::RegistryCreate, "registry_create"},
    {EventType::RegistrySet, "registry_set"},
    {EventType::RegistryDelete, "registry_delete"},
    {EventType::RegistryRename, "registry_rename"},
    {EventType::NetworkConnect, "network_connect"},
    {EventType::DnsQuery, "dns_query"},
}};

// String fields shared by lookup, parsing and serialization, in serialization order.
struct StringField {
  std::string_view name;
  std::string Event::* member;
};

const std::array<StringField, 27>& string_fields() {
  static const std::array<StringField, 27> fields{{
      {"image", &Event::image},
      {"command_line", &Event::command_line},
      {"user", &Event::user},
      {"integrity_level", &Event::integrity_level},
      {"hashes", &Event::hashes},
      {"process_guid", &Event::process_guid},
      {"parent_process_guid", &Event::parent_process_guid},
      {"parent_image", &Event::parent_image},
      {"parent_command_line", &Event::parent_command_line},
      {"target_path", &Event::target_path},
      {"new_path", &Event::new_path},
      {"details", &Event::details},
      {"registry_event_type", &Event::registry_event_type},
      {"target_image", &Event::target_image},
      {"granted_access", &Event::granted_access},
      {"image_loaded", &Event::image_loaded},
      {"signed", &Event::signed_flag},
      {"signature", &Event::signature},
      {"protocol", &Event::protocol},
      {"src_ip", &Event::src_ip},
      {"dest_ip", &Event::dest_ip},
      {"dest_hostname", &Event::dest_hostname},
      {"query_name", &Event::query_name},
      {"query_status", &Event::query_status},
      {"query_results", &Event::query_results},
      {"decoded_command", &Event::decoded_command},
      {"encoded_command_error", &Event::encoded_command_error},
  }};
  return fields;
}

FieldValue str_value(const std::string& s) {
  if (s.empty()) {
    return std::monostate{};
  }
  return s;
}

FieldValue int_value(const std::optional<std::int64_t>& v) {
  if (!v) {
    return std::monostate{};
  }
  return std::to_string(*v);
}

}  // namespace

std::string_view to_string(EventType type) {
  for (const auto& [t, name] : kTypeNames) {
    if (t == type) {
      return name;
    }
  }
  return "unknown";
}

std::optional<EventType> parse_event_type(std::string_view text) {
  for (const auto& [t, name] : kTypeNames) {
    if (name == text) {
      return t;
    }
  }
  return std::nullopt;
}

const std::vector<std::string_view>& all_event_type_names() {
  static const std::vector<std::string_view> names = [] {
    std::vector<std::string_view> v;
    v.reserve(kTypeNames.size());
    for (const auto& entry : kTypeNames) {
      v.push_back(entry.second);
    }
    return v;
  }();
  return names;
}

bool is_known_field(std::string_view name) {
  static const std::array<std::string_view, 11> extra{"host",
                                                      "source",
                                                      "type",
                                                      "pid",
                                                      "ppid",
                                                      "image_name",
                                                      "parent_image_name",
                                                      "ancestor_images",
                                                      "src_port",
                                                      "dest_port",
                                                      "initiated"};
  for (const auto& f : string_fields()) {
    if (f.name == name) {
      return true;
    }
  }
  for (const auto& e : extra) {
    if (e == name) {
      return true;
    }
  }
  return false;
}

FieldValue get_field(const Event& event, std::string_view name) {
  for (const auto& f : string_fields()) {
    if (f.name == name) {
      return str_value(event.*(f.member));
    }
  }
  if (name == "host") {
    return str_value(event.host);
  }
  if (name == "source") {
    return str_value(event.source);
  }
  if (name == "type") {
    return std::string(to_string(event.type));
  }
  if (name == "pid") {
    return std::to_string(event.pid);
  }
  if (name == "ppid") {
    return int_value(event.ppid);
  }
  if (name == "src_port") {
    return int_value(event.src_port);
  }
  if (name == "dest_port") {
    return int_value(event.dest_port);
  }
  if (name == "initiated") {
    if (!event.initiated) {
      return std::monostate{};
    }
    return std::string(*event.initiated ? "true" : "false");
  }
  if (name == "image_name") {
    return str_value(event.image_name);
  }
  if (name == "parent_image_name") {
    return str_value(event.parent_image_name);
  }
  if (name == "ancestor_images") {
    if (event.ancestor_images.empty()) {
      return std::monostate{};
    }
    return event.ancestor_images;
  }
  return std::monostate{};
}

std::variant<Event, EventParseError> event_from_json(const json::Value& value) {
  if (!value.is_object()) {
    return EventParseError{"event must be a JSON object"};
  }
  Event ev;
  auto required_string = [&](std::string_view key, std::string& out) -> bool {
    const json::Value* v = value.find(key);
    if (v == nullptr || !v->is_string() || v->as_string().empty()) {
      return false;
    }
    out = v->as_string();
    return true;
  };
  for (const std::string_view key : {"id", "ts", "host", "type"}) {
    std::string tmp;
    if (!required_string(key, tmp)) {
      return EventParseError{"missing or empty string field '" + std::string(key) + "'"};
    }
  }
  ev.id = value.find("id")->as_string();
  ev.host = value.find("host")->as_string();
  const std::string& ts_text = value.find("ts")->as_string();
  const auto ts = parse_ts(ts_text);
  if (!ts) {
    return EventParseError{"bad timestamp '" + ts_text + "'"};
  }
  ev.ts_ms = *ts;
  const auto type = parse_event_type(value.find("type")->as_string());
  if (!type) {
    return EventParseError{"unknown event type '" + value.find("type")->as_string() + "'"};
  }
  ev.type = *type;

  auto opt_int = [&](std::string_view key,
                     std::optional<std::int64_t>& out) -> std::optional<EventParseError> {
    const json::Value* v = value.find(key);
    if (v == nullptr || v->is_null()) {
      return std::nullopt;
    }
    if (!v->is_int()) {
      return EventParseError{std::string(key) + " must be an integer"};
    }
    out = v->as_int();
    return std::nullopt;
  };
  std::optional<std::int64_t> pid;
  if (auto err = opt_int("pid", pid)) {
    return *err;
  }
  if (!pid) {
    return EventParseError{"missing integer field 'pid'"};
  }
  ev.pid = *pid;
  for (const auto& [key, member] :
       std::array<std::pair<std::string_view, std::optional<std::int64_t> Event::*>, 5>{{
           {"ppid", &Event::ppid},
           {"src_port", &Event::src_port},
           {"dest_port", &Event::dest_port},
           {"sysmon_event_id", &Event::sysmon_event_id},
           {"record_id", &Event::record_id},
       }}) {
    if (auto err = opt_int(key, ev.*member)) {
      return *err;
    }
  }
  if (const json::Value* src = value.find("source"); src != nullptr && src->is_string()) {
    ev.source = src->as_string();
  }
  for (const auto& f : string_fields()) {
    const json::Value* v = value.find(f.name);
    if (v == nullptr || v->is_null()) {
      continue;
    }
    if (!v->is_string()) {
      return EventParseError{std::string(f.name) + " must be a string"};
    }
    ev.*(f.member) = v->as_string();
  }
  if (const json::Value* v = value.find("initiated"); v != nullptr && !v->is_null()) {
    if (!v->is_bool()) {
      return EventParseError{"initiated must be true or false"};
    }
    ev.initiated = v->as_bool();
  }
  return ev;
}

json::Value event_to_json(const Event& event) {
  json::Object o;
  o.emplace_back("id", event.id);
  o.emplace_back("ts", format_ts(event.ts_ms));
  o.emplace_back("host", event.host);
  if (!event.source.empty()) {
    o.emplace_back("source", event.source);
  }
  o.emplace_back("type", std::string(to_string(event.type)));
  if (event.sysmon_event_id) {
    o.emplace_back("sysmon_event_id", *event.sysmon_event_id);
  }
  if (event.record_id) {
    o.emplace_back("record_id", *event.record_id);
  }
  o.emplace_back("pid", event.pid);
  if (event.ppid) {
    o.emplace_back("ppid", *event.ppid);
  }
  for (const auto& f : string_fields()) {
    const std::string& s = event.*(f.member);
    if (!s.empty()) {
      o.emplace_back(std::string(f.name), s);
    }
  }
  if (event.initiated) {
    o.emplace_back("initiated", *event.initiated);
  }
  if (event.src_port) {
    o.emplace_back("src_port", *event.src_port);
  }
  if (event.dest_port) {
    o.emplace_back("dest_port", *event.dest_port);
  }
  return json::Value(std::move(o));
}

}  // namespace edr
