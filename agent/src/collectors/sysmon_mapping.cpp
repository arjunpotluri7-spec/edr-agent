#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "edr/sysmon.hpp"
#include "edr/textutil.hpp"

namespace edr {
namespace {

using DataMap = std::map<std::string, std::string, std::less<>>;

// Sysmon writes "-" for "not available".
std::string clean(std::string_view v) {
  return v == "-" ? std::string() : std::string(v);
}

std::string get(const DataMap& data, std::string_view key) {
  const auto it = data.find(key);
  return it == data.end() ? std::string() : clean(it->second);
}

std::optional<std::int64_t> get_int(const DataMap& data, std::string_view key) {
  const std::string v = get(data, key);
  if (v.empty()) {
    return std::nullopt;
  }
  return parse_int(v);
}

}  // namespace

bool sysmon_event_supported(int event_id) {
  switch (event_id) {
    case 1:
    case 3:
    case 5:
    case 7:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 22:
    case 23:
    case 26:
      return true;
    default:
      return false;
  }
}

std::variant<Event, MapError> map_sysmon_event(const xml::Element& event,
                                               const SysmonOptions& options) {
  if (event.name != "Event") {
    return MapError{"expected <Event>, found <" + event.name + ">"};
  }
  const xml::Element* system = event.child("System");
  if (system == nullptr) {
    return MapError{"missing <System>"};
  }
  const xml::Element* provider = system->child("Provider");
  if (provider == nullptr || provider->attribute("Name") != "Microsoft-Windows-Sysmon") {
    return MapError{"not a Microsoft-Windows-Sysmon record"};
  }
  const xml::Element* id_el = system->child("EventID");
  const auto event_id = id_el != nullptr ? parse_int(id_el->text) : std::nullopt;
  if (!event_id) {
    return MapError{"missing or invalid <EventID>"};
  }
  if (!sysmon_event_supported(static_cast<int>(*event_id))) {
    return MapError{"unsupported Sysmon event id " + std::to_string(*event_id)};
  }
  const xml::Element* rec_el = system->child("EventRecordID");
  const auto record = rec_el != nullptr ? parse_int(rec_el->text) : std::nullopt;
  if (!record) {
    return MapError{"missing or invalid <EventRecordID>"};
  }

  DataMap data;
  if (const xml::Element* ed = event.child("EventData"); ed != nullptr) {
    for (const auto& d : ed->children) {
      if (d.name == "Data") {
        if (const auto n = d.attribute("Name")) {
          data[std::string(*n)] = d.text;
        }
      }
    }
  }

  Event ev;
  ev.source = "sysmon";
  ev.sysmon_event_id = event_id;
  ev.record_id = record;
  if (!options.host_override.empty()) {
    ev.host = options.host_override;
  } else if (const xml::Element* c = system->child("Computer"); c != nullptr) {
    ev.host = c->text.substr(0, c->text.find('.'));
  }
  if (ev.host.empty()) {
    return MapError{"missing <Computer>"};
  }
  ev.id = "sysmon-" + ev.host + "-" + std::to_string(*record);

  std::optional<std::int64_t> ts = parse_ts(get(data, "UtcTime"));
  if (!ts) {
    if (const xml::Element* tc = system->child("TimeCreated"); tc != nullptr) {
      if (const auto st = tc->attribute("SystemTime")) {
        ts = parse_ts(*st);
      }
    }
  }
  if (!ts) {
    return MapError{"no usable UtcTime or TimeCreated"};
  }
  ev.ts_ms = *ts;

  const int id = static_cast<int>(*event_id);
  std::optional<std::int64_t> pid;
  if (id == 10) {
    pid = get_int(data, "SourceProcessId");
    ev.image = get(data, "SourceImage");
    ev.process_guid = get(data, "SourceProcessGUID");
    ev.user = get(data, "SourceUser");
  } else {
    pid = get_int(data, "ProcessId");
    ev.image = get(data, "Image");
    ev.process_guid = get(data, "ProcessGuid");
    ev.user = get(data, "User");
  }
  if (!pid) {
    return MapError{"missing or invalid ProcessId"};
  }
  ev.pid = *pid;

  switch (id) {
    case 1:
      ev.type = EventType::ProcessCreate;
      ev.command_line = get(data, "CommandLine");
      ev.integrity_level = get(data, "IntegrityLevel");
      ev.hashes = get(data, "Hashes");
      ev.ppid = get_int(data, "ParentProcessId");
      ev.parent_process_guid = get(data, "ParentProcessGuid");
      ev.parent_image = get(data, "ParentImage");
      ev.parent_command_line = get(data, "ParentCommandLine");
      break;
    case 3: {
      ev.type = EventType::NetworkConnect;
      ev.protocol = get(data, "Protocol");
      const std::string init = ascii_lower(get(data, "Initiated"));
      if (init == "true" || init == "false") {
        ev.initiated = init == "true";
      }
      ev.src_ip = get(data, "SourceIp");
      ev.src_port = get_int(data, "SourcePort");
      ev.dest_ip = get(data, "DestinationIp");
      ev.dest_port = get_int(data, "DestinationPort");
      ev.dest_hostname = get(data, "DestinationHostname");
      break;
    }
    case 5:
      ev.type = EventType::ProcessTerminate;
      break;
    case 7:
      ev.type = EventType::ImageLoad;
      ev.image_loaded = get(data, "ImageLoaded");
      ev.hashes = get(data, "Hashes");
      ev.signed_flag = get(data, "Signed");
      ev.signature = get(data, "Signature");
      break;
    case 10:
      ev.type = EventType::ProcessAccess;
      ev.target_image = get(data, "TargetImage");
      ev.granted_access = ascii_lower(get(data, "GrantedAccess"));
      break;
    case 11:
      ev.type = EventType::FileCreate;
      ev.target_path = get(data, "TargetFilename");
      break;
    case 12: {
      const std::string kind = get(data, "EventType");
      ev.registry_event_type = kind;
      ev.type = (kind == "DeleteKey" || kind == "DeleteValue") ? EventType::RegistryDelete
                                                               : EventType::RegistryCreate;
      ev.target_path = get(data, "TargetObject");
      break;
    }
    case 13:
      ev.type = EventType::RegistrySet;
      ev.registry_event_type = get(data, "EventType");
      ev.target_path = get(data, "TargetObject");
      ev.details = get(data, "Details");
      break;
    case 14:
      ev.type = EventType::RegistryRename;
      ev.registry_event_type = get(data, "EventType");
      ev.target_path = get(data, "TargetObject");
      ev.new_path = get(data, "NewName");
      break;
    case 22:
      ev.type = EventType::DnsQuery;
      ev.query_name = get(data, "QueryName");
      ev.query_status = get(data, "QueryStatus");
      ev.query_results = get(data, "QueryResults");
      break;
    case 23:
    case 26:
      ev.type = EventType::FileDelete;
      ev.target_path = get(data, "TargetFilename");
      ev.hashes = get(data, "Hashes");
      break;
    default:
      return MapError{"unsupported Sysmon event id " + std::to_string(id)};
  }
  return ev;
}

std::variant<SysmonBatch, xml::ParseError> parse_sysmon_xml(std::string_view text,
                                                            const SysmonOptions& options) {
  auto parsed = xml::parse(text);
  if (auto* err = std::get_if<xml::ParseError>(&parsed)) {
    return *err;
  }
  const xml::Element& doc = std::get<xml::Element>(parsed);
  const std::vector<xml::Element>* events = &doc.children;
  if (doc.children.size() == 1 && doc.children.front().name != "Event") {
    events = &doc.children.front().children;  // <Events> wrapper
  }
  SysmonBatch batch;
  for (const auto& el : *events) {
    if (el.name != "Event") {
      continue;
    }
    auto mapped = map_sysmon_event(el, options);
    if (auto* ev = std::get_if<Event>(&mapped)) {
      batch.events.push_back(std::move(*ev));
      continue;
    }
    const std::string& msg = std::get<MapError>(mapped).message;
    if (starts_with(msg, "unsupported Sysmon event id")) {
      ++batch.unsupported;
    } else {
      batch.errors.push_back(msg);
    }
  }
  return batch;
}

}  // namespace edr
