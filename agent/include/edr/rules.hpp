// Detection rules, scoring configuration and host baseline: types, loading and validation.
// The accepted schema is documented in docs/rules.md and enforced identically by
// server/src/edr_server/engine/config.py.
#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

#include "edr/event.hpp"
#include "edr/json.hpp"
#include "edr/netutil.hpp"

namespace edr {

enum class Severity { Low, Medium, High, Critical };
std::string_view to_string(Severity s);
std::optional<Severity> parse_severity(std::string_view text);

enum class Op {
  Equals,
  Contains,
  StartsWith,
  EndsWith,
  Regex,
  Gt,
  Gte,
  Lt,
  Lte,
  Exists,
  Cidr,
  MinLabelLength,
  MinLabelEntropy,
};

struct Leaf {
  std::string field;
  Op op = Op::Equals;
  bool case_sensitive = false;
  std::vector<std::string> strings;  // string ops (lower-cased unless case_sensitive)
  std::int64_t number = 0;           // gt/gte/lt/lte/min_label_length
  double real = 0.0;                 // min_label_entropy
  bool flag = false;                 // exists
  std::shared_ptr<std::regex> regex;
  std::vector<Cidr> cidrs;
};

struct Condition {
  enum class Kind { All, Any, Not, Leaf };
  Kind kind = Kind::Leaf;
  std::vector<Condition> children;
  Leaf leaf;
};

struct Rule {
  std::string id;
  std::string title;
  std::string description;
  Severity severity = Severity::Low;
  int points = 0;
  std::vector<std::string> attack;
  std::vector<EventType> event_types;
  Condition condition;
  std::string path;
};

struct Correlation {
  std::string id;
  std::string title;
  std::vector<std::string> requires_signals;
  bool ordered = false;
  std::int64_t within_ms = 0;
  int multiplier_percent = 100;
  int bonus = 0;
  int min_score = 0;
};

struct AnomalousOutbound {
  bool enabled = false;
  std::string id = "anomalous-outbound";
  std::string title = "Outbound connection not in the host baseline";
  Severity severity = Severity::Medium;
  int points = 25;
  std::vector<std::string> attack;
  bool learn = true;
  std::vector<Cidr> trusted;
  std::vector<Cidr> untrusted;
};

struct Scoring {
  std::int64_t window_ms = 600000;
  int incident_threshold = 50;
  int incident_min_distinct = 2;  // distinct rule ids needed (critical signals are exempt)
  std::vector<std::pair<std::string, int>> labels;  // ascending by minimum
  std::array<int, 4> severity_points{10, 25, 40, 60};
  int decay_percent = 50;
  int max_counted = 3;
  int low_severity_cap = 20;
  std::set<std::string> boundary_images;  // lower-case file names
  int max_depth = 16;
  AnomalousOutbound anomalous;
  std::vector<Correlation> correlations;

  [[nodiscard]] std::string label_for(int score) const;
};

struct RuleSet {
  std::vector<Rule> rules;  // sorted by id
};

// (host, image file name lower-case, destination IP lower-case)
using BaselineKey = std::tuple<std::string, std::string, std::string>;
using Baseline = std::set<BaselineKey>;

struct ConfigError {
  std::string message;
};

template <typename T>
using Loaded = std::variant<T, ConfigError>;

Loaded<Condition> parse_condition(const json::Value& raw, const std::string& where, int depth = 0);
Loaded<Rule> parse_rule(const json::Value& raw, const std::string& where, const Scoring& scoring);
Loaded<Scoring> parse_scoring(const json::Value& raw, const std::string& where);
Loaded<Baseline> parse_baseline(const json::Value& raw, const std::string& where);

// Reads and parses a YAML file (size-capped) into a JSON value.
Loaded<json::Value> read_yaml_file(const std::filesystem::path& path);
Loaded<Scoring> load_scoring(const std::filesystem::path& path);
// Loads every *.yaml file in dir (sorted by name), one rule per file, and checks that every
// correlation only requires known signal ids.
Loaded<RuleSet> load_rules(const std::filesystem::path& dir, const Scoring& scoring);
Loaded<Baseline> load_baseline(const std::filesystem::path& path);

// Reads a whole file with a size cap. nullopt + message on failure.
std::variant<std::string, ConfigError> read_file_capped(const std::filesystem::path& path,
                                                        std::uintmax_t max_bytes);

}  // namespace edr
