#include "edr/rules.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "edr/textutil.hpp"
#include "edr/yaml.hpp"

namespace edr {

namespace {

constexpr std::uintmax_t kMaxRuleFileBytes = std::uintmax_t{256} * 1024;
constexpr std::size_t kMaxRules = 500;
constexpr std::array<std::string_view, 4> kSeverities{"low", "medium", "high", "critical"};

// Internal: validation failures unwind to the public API functions, which return ConfigError.
struct Invalid : std::exception {
  explicit Invalid(std::string msg) : message(std::move(msg)) {}
  [[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
  std::string message;
};

[[noreturn]] void fail(const std::string& where, const std::string& message) {
  throw Invalid(where + ": " + message);
}

bool valid_id(std::string_view id) {
  static const std::regex re("[a-z0-9][a-z0-9-]{1,63}");
  return std::regex_match(id.begin(), id.end(), re);
}

bool valid_attack(std::string_view id) {
  static const std::regex re(R"(T[0-9]{4}(\.[0-9]{3})?)");
  return std::regex_match(id.begin(), id.end(), re);
}

const json::Object& as_mapping(const json::Value* v, const std::string& where) {
  if (v == nullptr || !v->is_object()) {
    fail(where, "must be a mapping");
  }
  return v->as_object();
}

void check_keys(const json::Value* v, const std::set<std::string>& allowed,
                const std::string& where) {
  const json::Object& obj = as_mapping(v, where);
  std::vector<std::string> unknown;
  for (const auto& [k, _] : obj) {
    if (allowed.count(k) == 0) {
      unknown.push_back(k);
    }
  }
  if (!unknown.empty()) {
    std::sort(unknown.begin(), unknown.end());
    std::string joined;
    for (const auto& k : unknown) {
      joined += (joined.empty() ? "" : ", ") + k;
    }
    fail(where, "unknown key(s): " + joined);
  }
}

int get_int(const json::Value& obj, const std::string& key, const std::string& where, int lo,
            int hi, std::optional<int> fallback = std::nullopt) {
  const json::Value* v = obj.find(key);
  if (v == nullptr) {
    if (!fallback) {
      fail(where, "missing required key '" + key + "'");
    }
    return *fallback;
  }
  if (!v->is_int() || v->as_int() < lo || v->as_int() > hi) {
    fail(where,
         key + " must be an integer from " + std::to_string(lo) + " to " + std::to_string(hi));
  }
  return static_cast<int>(v->as_int());
}

bool get_bool(const json::Value& obj, const std::string& key, const std::string& where,
              bool fallback) {
  const json::Value* v = obj.find(key);
  if (v == nullptr) {
    return fallback;
  }
  if (!v->is_bool()) {
    fail(where, key + " must be true or false");
  }
  return v->as_bool();
}

std::vector<std::string> string_list(const json::Value* v, const std::string& where,
                                     const std::string& key) {
  if (v == nullptr || !v->is_array() || v->as_array().empty()) {
    fail(where, key + " must be a non-empty list of strings");
  }
  std::vector<std::string> out;
  for (const auto& item : v->as_array()) {
    if (!item.is_string()) {
      fail(where, key + " must be a non-empty list of strings");
    }
    out.push_back(item.as_string());
  }
  return out;
}

std::vector<Cidr> cidr_list(const json::Value* v, const std::string& where) {
  std::vector<Cidr> out;
  if (v == nullptr || v->is_null()) {
    return out;
  }
  if (!v->is_array()) {
    fail(where, "must be a list of CIDR strings");
  }
  for (const auto& item : v->as_array()) {
    std::optional<Cidr> c;
    if (item.is_string()) {
      c = parse_cidr(item.as_string());
    }
    if (!c) {
      fail(where,
           "invalid CIDR " + (item.is_string() ? "'" + item.as_string() + "'" : json::dump(item)));
    }
    out.push_back(*c);
  }
  return out;
}

Severity severity_from(const json::Value* v, const std::string& where) {
  std::optional<Severity> s;
  if (v != nullptr && v->is_string()) {
    s = parse_severity(v->as_string());
  }
  if (!s) {
    fail(where, "severity must be one of low, medium, high, critical");
  }
  return *s;
}

const std::set<std::string>& leaf_ops() {
  static const std::set<std::string> ops{"equals",
                                         "contains",
                                         "startswith",
                                         "endswith",
                                         "regex",
                                         "gt",
                                         "gte",
                                         "lt",
                                         "lte",
                                         "exists",
                                         "cidr",
                                         "min_label_length",
                                         "min_label_entropy"};
  return ops;
}

Leaf parse_leaf(const json::Value& raw, const std::string& where) {
  const json::Value* fv = raw.find("field");
  if (fv == nullptr) {
    fail(where, "condition needs 'field' or one of all/any/not");
  }
  if (!fv->is_string() || !is_known_field(fv->as_string())) {
    fail(where,
         "unknown field " + (fv->is_string() ? "'" + fv->as_string() + "'" : json::dump(*fv)));
  }
  Leaf leaf;
  leaf.field = fv->as_string();
  leaf.case_sensitive = get_bool(raw, "case_sensitive", where, false);
  std::vector<std::string> ops;
  for (const auto& [k, _] : raw.as_object()) {
    if (k != "field" && k != "case_sensitive") {
      ops.push_back(k);
    }
  }
  if (ops.size() != 1 || leaf_ops().count(ops[0]) == 0) {
    std::string all;
    for (const auto& o : leaf_ops()) {
      all += (all.empty() ? "" : ", ") + o;
    }
    std::string got;
    for (const auto& o : ops) {
      got += (got.empty() ? "" : ", ") + o;
    }
    fail(where, "field '" + leaf.field + "' needs exactly one operator from " + all + " (got " +
                    (got.empty() ? "none" : got) + ")");
  }
  const std::string& op = ops[0];
  const json::Value& value = *raw.find(op);
  if (op == "equals" || op == "contains" || op == "startswith" || op == "endswith") {
    leaf.op = op == "equals"       ? Op::Equals
              : op == "contains"   ? Op::Contains
              : op == "startswith" ? Op::StartsWith
                                   : Op::EndsWith;
    std::vector<json::Value> items =
        value.is_array() ? value.as_array() : std::vector<json::Value>{value};
    if (items.empty()) {
      fail(where, op + " needs a non-empty string or list of strings");
    }
    for (const auto& item : items) {
      if (!item.is_string() || item.as_string().empty()) {
        fail(where, op + " needs a non-empty string or list of strings");
      }
      leaf.strings.push_back(leaf.case_sensitive ? item.as_string()
                                                 : ascii_lower(item.as_string()));
    }
    return leaf;
  }
  if (op == "regex") {
    if (!value.is_string() || value.as_string().empty()) {
      fail(where, "regex needs a non-empty string");
    }
    auto flags = std::regex::ECMAScript;
    if (!leaf.case_sensitive) {
      flags |= std::regex::icase;
    }
    try {
      leaf.regex = std::make_shared<std::regex>(value.as_string(), flags);
    } catch (const std::regex_error& e) {
      fail(where, std::string("invalid regex: ") + e.what());
    }
    leaf.op = Op::Regex;
    leaf.strings.push_back(value.as_string());
    return leaf;
  }
  if (op == "gt" || op == "gte" || op == "lt" || op == "lte" || op == "min_label_length") {
    if (!value.is_int()) {
      fail(where, op + " needs an integer");
    }
    leaf.op = op == "gt"    ? Op::Gt
              : op == "gte" ? Op::Gte
              : op == "lt"  ? Op::Lt
              : op == "lte" ? Op::Lte
                            : Op::MinLabelLength;
    leaf.number = value.as_int();
    return leaf;
  }
  if (op == "min_label_entropy") {
    if (!value.is_number() || value.as_double() < 0 || value.as_double() > 8) {
      fail(where, "min_label_entropy needs a number from 0 to 8");
    }
    leaf.op = Op::MinLabelEntropy;
    leaf.real = value.as_double();
    return leaf;
  }
  if (op == "exists") {
    if (!value.is_bool()) {
      fail(where, "exists needs true or false");
    }
    leaf.op = Op::Exists;
    leaf.flag = value.as_bool();
    return leaf;
  }
  // cidr
  leaf.op = Op::Cidr;
  std::vector<json::Value> items =
      value.is_array() ? value.as_array() : std::vector<json::Value>{value};
  for (const auto& item : items) {
    std::optional<Cidr> c;
    if (item.is_string()) {
      c = parse_cidr(item.as_string());
    }
    if (!c) {
      fail(where, "invalid CIDR " + json::dump(item));
    }
    leaf.cidrs.push_back(*c);
    leaf.strings.push_back(item.as_string());
  }
  if (leaf.cidrs.empty()) {
    fail(where, "cidr needs at least one network");
  }
  return leaf;
}

Condition condition_impl(const json::Value& raw, const std::string& where, int depth) {
  if (depth > 16) {
    fail(where, "condition nested too deeply (max 16)");
  }
  if (!raw.is_object()) {
    fail(where, "condition must be a mapping");
  }
  for (const char* kind : {"all", "any", "not"}) {
    const json::Value* v = raw.find(kind);
    if (v == nullptr) {
      continue;
    }
    if (raw.as_object().size() != 1) {
      fail(where, std::string(kind) + " must be the only key in its mapping");
    }
    Condition c;
    if (std::string_view(kind) == "not") {
      c.kind = Condition::Kind::Not;
      c.children.push_back(condition_impl(*v, where, depth + 1));
      return c;
    }
    c.kind = std::string_view(kind) == "all" ? Condition::Kind::All : Condition::Kind::Any;
    if (!v->is_array() || v->as_array().empty()) {
      fail(where, std::string(kind) + " needs a non-empty list");
    }
    for (const auto& child : v->as_array()) {
      c.children.push_back(condition_impl(child, where, depth + 1));
    }
    return c;
  }
  Condition c;
  c.kind = Condition::Kind::Leaf;
  c.leaf = parse_leaf(raw, where);
  return c;
}

Rule rule_impl(const json::Value& raw, const std::string& where, const Scoring& scoring) {
  if (!raw.is_object()) {
    fail(where, "a rule file must contain a mapping");
  }
  check_keys(
      &raw,
      {"id", "title", "description", "severity", "points", "attack", "event_types", "condition"},
      where);
  for (const char* key : {"id", "title", "severity", "event_types", "condition"}) {
    if (raw.find(key) == nullptr) {
      fail(where, std::string("missing required key '") + key + "'");
    }
  }
  Rule r;
  r.path = where;
  const json::Value* id = raw.find("id");
  if (!id->is_string() || !valid_id(id->as_string())) {
    fail(where, "id must match [a-z0-9][a-z0-9-]{1,63}");
  }
  r.id = id->as_string();
  const json::Value* title = raw.find("title");
  if (!title->is_string()) {
    fail(where, "title must be a non-empty string");
  }
  std::string t = title->as_string();
  while (!t.empty() && (t.back() == ' ' || t.back() == '\t' || t.back() == '\n')) {
    t.pop_back();
  }
  std::size_t lead = 0;
  while (lead < t.size() && (t[lead] == ' ' || t[lead] == '\t' || t[lead] == '\n')) {
    ++lead;
  }
  r.title = t.substr(lead);
  if (r.title.empty()) {
    fail(where, "title must be a non-empty string");
  }
  if (const json::Value* d = raw.find("description"); d != nullptr) {
    if (!d->is_string()) {
      fail(where, "description must be a string");
    }
    r.description = d->as_string();
  }
  r.severity = severity_from(raw.find("severity"), where);
  r.points = get_int(raw, "points", where, 0, 100,
                     scoring.severity_points.at(static_cast<std::size_t>(r.severity)));
  if (raw.find("attack") != nullptr) {
    r.attack = string_list(raw.find("attack"), where, "attack");
    for (const auto& a : r.attack) {
      if (!valid_attack(a)) {
        fail(where, "'" + a + "' is not an ATT&CK technique id like T1059.001");
      }
    }
  }
  for (const auto& name : string_list(raw.find("event_types"), where, "event_types")) {
    const auto type = parse_event_type(name);
    if (!type) {
      fail(where, "unknown event type '" + name + "'");
    }
    r.event_types.push_back(*type);
  }
  r.condition = condition_impl(*raw.find("condition"), where + " (rule " + r.id + ")", 0);
  return r;
}

int multiplier_percent(const json::Value* v, const std::string& where) {
  if (v == nullptr) {
    return 100;
  }
  if (!v->is_number() || v->as_double() < 1 || v->as_double() > 10) {
    fail(where, "multiplier must be a number from 1 to 10");
  }
  const double scaled = v->as_double() * 100;
  const auto pct = static_cast<int>(std::llround(scaled));
  if (std::fabs(static_cast<double>(pct) - scaled) > 1e-6) {
    fail(where, "multiplier may have at most two decimal places");
  }
  return pct;
}

Scoring scoring_impl(const json::Value& top, const std::string& where) {
  check_keys(&top,
             {"version", "window_minutes", "incident_threshold", "incident_min_distinct_signals",
              "labels", "severity_points", "repeats", "low_severity_cap", "tree",
              "anomalous_outbound", "correlations"},
             where);
  const json::Value* version = top.find("version");
  if (version == nullptr || !version->is_int() || version->as_int() != 1) {
    fail(where, "version must be 1");
  }
  Scoring s;
  s.window_ms = static_cast<std::int64_t>(get_int(top, "window_minutes", where, 1, 1440)) * 60000;
  s.incident_threshold = get_int(top, "incident_threshold", where, 1, 100);
  s.incident_min_distinct = get_int(top, "incident_min_distinct_signals", where, 1, 10, 2);

  const std::string lw = where + ": labels";
  check_keys(top.find("labels"), {"low", "medium", "high", "critical"}, lw);
  for (const auto sev : kSeverities) {
    s.labels.emplace_back(std::string(sev),
                          get_int(*top.find("labels"), std::string(sev), lw, 0, 100));
  }
  std::stable_sort(s.labels.begin(), s.labels.end(),
                   [](const auto& a, const auto& b) { return a.second < b.second; });
  if (s.labels.front().second != 0) {
    fail(where, "labels need one entry with minimum 0");
  }

  const std::string spw = where + ": severity_points";
  check_keys(top.find("severity_points"), {"low", "medium", "high", "critical"}, spw);
  for (std::size_t i = 0; i < kSeverities.size(); ++i) {
    s.severity_points.at(i) =
        get_int(*top.find("severity_points"), std::string(kSeverities.at(i)), spw, 0, 100);
  }

  const json::Value empty_obj{json::Object{}};
  const json::Value* rep = top.find("repeats") != nullptr ? top.find("repeats") : &empty_obj;
  check_keys(rep, {"decay_percent", "max_counted"}, where + ": repeats");
  s.decay_percent = get_int(*rep, "decay_percent", where + ": repeats", 0, 100, 50);
  s.max_counted = get_int(*rep, "max_counted", where + ": repeats", 1, 100, 3);
  s.low_severity_cap = get_int(top, "low_severity_cap", where, 0, 100, 20);

  const json::Value* tree = top.find("tree") != nullptr ? top.find("tree") : &empty_obj;
  check_keys(tree, {"boundary_images", "max_depth"}, where + ": tree");
  if (const json::Value* b = tree->find("boundary_images"); b != nullptr) {
    if (!b->is_array()) {
      fail(where, "tree.boundary_images must be a list of file names");
    }
    for (const auto& item : b->as_array()) {
      if (!item.is_string()) {
        fail(where, "tree.boundary_images must be a list of file names");
      }
      s.boundary_images.insert(ascii_lower(item.as_string()));
    }
  }
  s.max_depth = get_int(*tree, "max_depth", where + ": tree", 1, 64, 16);

  const std::string aw = where + ": anomalous_outbound";
  json::Value disabled{json::Object{}};
  disabled.set("enabled", false);
  const json::Value* ao =
      top.find("anomalous_outbound") != nullptr ? top.find("anomalous_outbound") : &disabled;
  check_keys(ao,
             {"enabled", "id", "title", "severity", "points", "attack", "learn", "trusted_cidrs",
              "untrusted_cidrs"},
             aw);
  AnomalousOutbound& a = s.anomalous;
  a.enabled = get_bool(*ao, "enabled", aw, true);
  if (const json::Value* v = ao->find("id"); v != nullptr) {
    if (!v->is_string() || !valid_id(v->as_string())) {
      fail(aw, "id must match [a-z0-9][a-z0-9-]{1,63}");
    }
    a.id = v->as_string();
  }
  a.severity =
      ao->find("severity") != nullptr ? severity_from(ao->find("severity"), aw) : Severity::Medium;
  if (const json::Value* v = ao->find("title"); v != nullptr) {
    if (!v->is_string() || v->as_string().empty()) {
      fail(aw, "title must be a non-empty string");
    }
    a.title = v->as_string();
  }
  if (const json::Value* v = ao->find("attack"); v != nullptr) {
    if (!v->is_array()) {
      fail(aw, "attack must be a list of technique ids");
    }
    for (const auto& item : v->as_array()) {
      if (!item.is_string() || !valid_attack(item.as_string())) {
        fail(aw, "attack must be a list of technique ids");
      }
      a.attack.push_back(item.as_string());
    }
  }
  a.learn = get_bool(*ao, "learn", aw, true);
  a.trusted = cidr_list(ao->find("trusted_cidrs"), aw + ": trusted_cidrs");
  a.untrusted = cidr_list(ao->find("untrusted_cidrs"), aw + ": untrusted_cidrs");
  a.points = get_int(*ao, "points", aw, 0, 100,
                     s.severity_points.at(static_cast<std::size_t>(a.severity)));

  if (const json::Value* list = top.find("correlations"); list != nullptr) {
    if (!list->is_array()) {
      fail(where, "correlations must be a list");
    }
    std::set<std::string> seen;
    for (std::size_t i = 0; i < list->as_array().size(); ++i) {
      const json::Value& c = list->as_array()[i];
      const std::string cw = where + ": correlations[" + std::to_string(i) + "]";
      check_keys(&c,
                 {"id", "title", "requires", "ordered", "within_minutes", "multiplier", "bonus",
                  "min_score"},
                 cw);
      Correlation corr;
      const json::Value* id = c.find("id");
      if (id == nullptr || !id->is_string() || !valid_id(id->as_string())) {
        fail(cw, "id must match [a-z0-9][a-z0-9-]{1,63}");
      }
      corr.id = id->as_string();
      if (!seen.insert(corr.id).second) {
        fail(cw, "duplicate correlation id '" + corr.id + "'");
      }
      corr.title = corr.id;
      if (const json::Value* t = c.find("title"); t != nullptr) {
        if (!t->is_string() || t->as_string().empty()) {
          fail(cw, "title must be a non-empty string");
        }
        corr.title = t->as_string();
      }
      const json::Value* req = c.find("requires");
      std::set<std::string> distinct;
      if (req != nullptr && req->is_array()) {
        for (const auto& r : req->as_array()) {
          if (!r.is_string()) {
            distinct.clear();
            break;
          }
          distinct.insert(r.as_string());
          corr.requires_signals.push_back(r.as_string());
        }
      }
      if (corr.requires_signals.size() < 2 || distinct.size() != corr.requires_signals.size()) {
        fail(cw, "requires needs two or more distinct signal ids");
      }
      corr.ordered = get_bool(c, "ordered", cw, false);
      corr.within_ms = static_cast<std::int64_t>(get_int(c, "within_minutes", cw, 1, 1440,
                                                         static_cast<int>(s.window_ms / 60000))) *
                       60000;
      corr.multiplier_percent = multiplier_percent(c.find("multiplier"), cw);
      corr.bonus = get_int(c, "bonus", cw, 0, 100, 0);
      corr.min_score = get_int(c, "min_score", cw, 0, 100, 0);
      if (corr.multiplier_percent == 100 && corr.bonus == 0 && corr.min_score == 0) {
        fail(cw, "set at least one of multiplier, bonus or min_score");
      }
      s.correlations.push_back(std::move(corr));
    }
  }
  return s;
}

Baseline baseline_impl(const json::Value& raw, const std::string& where) {
  const json::Value* version = raw.find("version");
  const json::Value* pairs = raw.find("pairs");
  if (!raw.is_object() || version == nullptr || !version->is_int() || version->as_int() != 1 ||
      pairs == nullptr || !pairs->is_array()) {
    fail(where, "expected {\"version\": 1, \"pairs\": [...]}");
  }
  Baseline out;
  for (std::size_t i = 0; i < pairs->as_array().size(); ++i) {
    const json::Value& p = pairs->as_array()[i];
    const std::string pw = "pairs[" + std::to_string(i) + "]";
    if (!p.is_object() || p.as_object().size() != 3 || p.find("host") == nullptr ||
        p.find("image") == nullptr || p.find("dest") == nullptr) {
      fail(where, pw + " needs exactly host, image and dest");
    }
    for (const char* k : {"host", "image", "dest"}) {
      if (!p.find(k)->is_string() || p.find(k)->as_string().empty()) {
        fail(where, pw + " values must be non-empty strings");
      }
    }
    if (!parse_ip(p.find("dest")->as_string())) {
      fail(where, pw + ".dest is not an IP address");
    }
    out.emplace(p.find("host")->as_string(), ascii_lower(p.find("image")->as_string()),
                ascii_lower(p.find("dest")->as_string()));
  }
  return out;
}

template <typename Fn>
auto guarded(const Fn& fn) -> Loaded<decltype(fn())> {
  try {
    return fn();
  } catch (const Invalid& e) {
    return ConfigError{e.message};
  }
}

}  // namespace

std::string_view to_string(Severity s) {
  return kSeverities.at(static_cast<std::size_t>(s));
}

std::optional<Severity> parse_severity(std::string_view text) {
  for (std::size_t i = 0; i < kSeverities.size(); ++i) {
    if (kSeverities.at(i) == text) {
      return static_cast<Severity>(i);
    }
  }
  return std::nullopt;
}

std::string Scoring::label_for(int score) const {
  std::string label = labels.empty() ? "low" : labels.front().first;
  for (const auto& [name, minimum] : labels) {
    if (score >= minimum) {
      label = name;
    }
  }
  return label;
}

Loaded<Condition> parse_condition(const json::Value& raw, const std::string& where, int depth) {
  return guarded([&] { return condition_impl(raw, where, depth); });
}

Loaded<Rule> parse_rule(const json::Value& raw, const std::string& where, const Scoring& scoring) {
  return guarded([&] { return rule_impl(raw, where, scoring); });
}

Loaded<Scoring> parse_scoring(const json::Value& raw, const std::string& where) {
  return guarded([&] { return scoring_impl(raw, where); });
}

Loaded<Baseline> parse_baseline(const json::Value& raw, const std::string& where) {
  return guarded([&] { return baseline_impl(raw, where); });
}

std::variant<std::string, ConfigError> read_file_capped(const std::filesystem::path& path,
                                                        std::uintmax_t max_bytes) {
  std::error_code ec;
  if (!std::filesystem::is_regular_file(path, ec)) {
    return ConfigError{path.string() + ": not a regular file"};
  }
  const std::uintmax_t size = std::filesystem::file_size(path, ec);
  if (ec) {
    return ConfigError{path.string() + ": cannot read: " + ec.message()};
  }
  if (size > max_bytes) {
    return ConfigError{path.string() + ": file is larger than " + std::to_string(max_bytes) +
                       " bytes"};
  }
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return ConfigError{path.string() + ": cannot open"};
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  std::string text = ss.str();
  if (text.size() > max_bytes) {
    return ConfigError{path.string() + ": file grew while reading"};
  }
  return text;
}

Loaded<json::Value> read_yaml_file(const std::filesystem::path& path) {
  auto text = read_file_capped(path, kMaxRuleFileBytes);
  if (auto* err = std::get_if<ConfigError>(&text)) {
    return *err;
  }
  auto parsed = yaml::parse(std::get<std::string>(text));
  if (auto* err = std::get_if<yaml::ParseError>(&parsed)) {
    return ConfigError{path.string() + ":" + std::to_string(err->line) +
                       ": cannot parse YAML: " + err->message};
  }
  return std::get<json::Value>(std::move(parsed));
}

Loaded<Scoring> load_scoring(const std::filesystem::path& path) {
  auto raw = read_yaml_file(path);
  if (auto* err = std::get_if<ConfigError>(&raw)) {
    return *err;
  }
  return parse_scoring(std::get<json::Value>(raw), path.string());
}

Loaded<RuleSet> load_rules(const std::filesystem::path& dir, const Scoring& scoring) {
  std::error_code ec;
  if (!std::filesystem::is_directory(dir, ec)) {
    return ConfigError{dir.string() + ": not a directory"};
  }
  std::vector<std::filesystem::path> files;
  for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
    if (entry.path().extension() == ".yaml" && entry.is_regular_file(ec)) {
      files.push_back(entry.path());
    }
  }
  if (ec) {
    return ConfigError{dir.string() + ": cannot list: " + ec.message()};
  }
  std::sort(files.begin(), files.end(), [](const auto& a, const auto& b) {
    return a.filename().string() < b.filename().string();
  });
  if (files.empty()) {
    return ConfigError{dir.string() + ": no .yaml rule files found"};
  }
  if (files.size() > kMaxRules) {
    return ConfigError{dir.string() + ": more than " + std::to_string(kMaxRules) + " rule files"};
  }
  RuleSet set;
  std::set<std::string> seen;
  for (const auto& path : files) {
    auto raw = read_yaml_file(path);
    if (auto* err = std::get_if<ConfigError>(&raw)) {
      return *err;
    }
    auto rule = parse_rule(std::get<json::Value>(raw), path.string(), scoring);
    if (auto* err = std::get_if<ConfigError>(&rule)) {
      return *err;
    }
    Rule& r = std::get<Rule>(rule);
    if (!seen.insert(r.id).second || r.id == scoring.anomalous.id) {
      return ConfigError{path.string() + ": duplicate rule id '" + r.id + "'"};
    }
    set.rules.push_back(std::move(r));
  }
  std::sort(set.rules.begin(), set.rules.end(),
            [](const Rule& a, const Rule& b) { return a.id < b.id; });
  if (scoring.anomalous.enabled) {
    seen.insert(scoring.anomalous.id);
  }
  for (const auto& corr : scoring.correlations) {
    for (const auto& req : corr.requires_signals) {
      if (seen.count(req) == 0) {
        return ConfigError{"scoring: correlation '" + corr.id + "' requires unknown signal '" +
                           req + "'"};
      }
    }
  }
  return set;
}

Loaded<Baseline> load_baseline(const std::filesystem::path& path) {
  auto text = read_file_capped(path, std::uintmax_t{16} * 1024 * 1024);
  if (auto* err = std::get_if<ConfigError>(&text)) {
    return *err;
  }
  auto parsed = json::parse(std::get<std::string>(text));
  if (auto* err = std::get_if<json::ParseError>(&parsed)) {
    return ConfigError{path.string() + ": cannot read baseline: " + err->message};
  }
  return parse_baseline(std::get<json::Value>(parsed), path.string());
}

}  // namespace edr
