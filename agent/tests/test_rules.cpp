#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <variant>

#include "edr/rules.hpp"
#include "edr/scorer.hpp"
#include "edr/yaml.hpp"
#include "test_util.hpp"

namespace edr {
namespace {

std::string rule_error(const std::string& yaml_text) {
  auto raw = yaml::parse(yaml_text);
  if (auto* e = std::get_if<yaml::ParseError>(&raw)) {
    return "yaml: " + e->message;
  }
  const Scoring s = test::shipped_scoring();
  auto r = parse_rule(std::get<json::Value>(raw), "t.yaml", s);
  if (auto* e = std::get_if<ConfigError>(&r)) {
    return e->message;
  }
  return "";
}

TEST(Rules, ShippedRulesLoad) {
  const Scoring s = test::shipped_scoring();
  const RuleSet rules = test::shipped_rules(s);
  EXPECT_EQ(rules.rules.size(), 13U);
  EXPECT_TRUE(std::is_sorted(rules.rules.begin(), rules.rules.end(),
                             [](const Rule& a, const Rule& b) { return a.id < b.id; }));
  EXPECT_EQ(s.correlations.size(), 4U);
  EXPECT_EQ(s.window_ms, 10 * 60000);
  EXPECT_TRUE(s.anomalous.enabled);
  EXPECT_EQ(s.anomalous.points, 35);
  EXPECT_EQ(s.label_for(0), "low");
  EXPECT_EQ(s.label_for(30), "medium");
  EXPECT_EQ(s.label_for(79), "high");
  EXPECT_EQ(s.label_for(100), "critical");
}

// samples/rule_cases.jsonl holds a positive and a negative case for every rule; the Python
// engine runs the same file (server/tests/test_rules.py).
TEST(Rules, EveryRuleCaseFromTheSharedFile) {
  std::istringstream in(test::read_text(test::repo() / "samples" / "rule_cases.jsonl"));
  std::string line;
  std::set<std::string> positive;
  std::set<std::string> negative;
  int cases = 0;
  while (std::getline(in, line)) {
    if (line.empty()) {
      continue;
    }
    const json::Value c = test::parse_json(line);
    const std::string rule = c.find("rule")->as_string();
    const bool expect = c.find("expect")->as_bool();
    Engine engine = test::shipped_engine(false);
    const auto signals = engine.match(test::make_event(*c.find("event")));
    const bool fired = std::any_of(signals.begin(), signals.end(),
                                   [&](const Signal& s) { return s.rule_id == rule; });
    EXPECT_EQ(fired, expect) << rule << ": " << c.find("name")->as_string();
    (expect ? positive : negative).insert(rule);
    ++cases;
  }
  EXPECT_GE(cases, 26);
  const RuleSet rules = test::shipped_rules(test::shipped_scoring());
  for (const auto& r : rules.rules) {
    EXPECT_EQ(positive.count(r.id), 1U) << "no positive case for " << r.id;
    EXPECT_EQ(negative.count(r.id), 1U) << "no negative case for " << r.id;
  }
}

TEST(Rules, ParentChildFromProcessContext) {
  // The child event has no parent_image field: the engine fills it from the process table.
  Engine engine = test::shipped_engine(false);
  engine.match(test::make_event_text(
      R"({"id":"a","ts":"2026-10-20T10:00:00Z","host":"H","type":"process_create","pid":10,)"
      R"("image":"C:\\Office\\WINWORD.EXE"})"));
  const auto sigs = engine.match(test::make_event_text(
      R"({"id":"b","ts":"2026-10-20T10:00:01Z","host":"H","type":"process_create","pid":11,)"
      R"("ppid":10,"image":"C:\\Windows\\System32\\cmd.exe","command_line":"cmd /c echo"})"));
  ASSERT_EQ(sigs.size(), 1U);
  EXPECT_EQ(sigs[0].rule_id, "office-spawns-script-host");
}

TEST(Rules, ValidationErrorsAreSpecific) {
  const std::string base = "id: x1\ntitle: T\nseverity: low\nevent_types: [dns_query]\n";
  EXPECT_EQ(rule_error(base + "condition:\n  field: query_name\n  contains: a\n"), "");
  EXPECT_NE(rule_error(base + "condition:\n  field: nope\n  contains: a\n").find("unknown field"),
            std::string::npos);
  EXPECT_NE(rule_error(base + "condition:\n  field: image\n").find("exactly one operator"),
            std::string::npos);
  EXPECT_NE(rule_error(base + "condition:\n  field: image\n  regex: '('\n").find("invalid regex"),
            std::string::npos);
  EXPECT_NE(rule_error(base + "condition:\n  field: dest_ip\n  cidr: [10.0.0.0/40]\n")
                .find("invalid CIDR"),
            std::string::npos);
  EXPECT_NE(rule_error(base + "condition:\n  all: []\n").find("non-empty list"), std::string::npos);
  EXPECT_NE(rule_error(base + "extra: 1\ncondition:\n  field: image\n  exists: true\n")
                .find("unknown key"),
            std::string::npos);
  EXPECT_NE(rule_error("id: X!\ntitle: T\nseverity: low\nevent_types: [dns_query]\n"
                       "condition:\n  field: image\n  exists: true\n")
                .find("id must match"),
            std::string::npos);
  EXPECT_NE(rule_error("id: x1\ntitle: T\nseverity: bad\nevent_types: [dns_query]\n"
                       "condition:\n  field: image\n  exists: true\n")
                .find("severity"),
            std::string::npos);
  EXPECT_NE(rule_error("id: x1\ntitle: T\nseverity: low\nevent_types: [nope]\n"
                       "condition:\n  field: image\n  exists: true\n")
                .find("unknown event type"),
            std::string::npos);
  EXPECT_NE(rule_error(base + "attack: [X1]\ncondition:\n  field: image\n  exists: true\n")
                .find("ATT&CK"),
            std::string::npos);
}

TEST(Rules, ScoringValidation) {
  auto bad = [](const std::string& text) {
    auto raw = yaml::parse(text);
    if (std::holds_alternative<yaml::ParseError>(raw)) {
      return std::string("yaml");
    }
    auto s = parse_scoring(std::get<json::Value>(raw), "s.yaml");
    return std::holds_alternative<ConfigError>(s) ? std::get<ConfigError>(s).message
                                                  : std::string();
  };
  const std::string base =
      "version: 1\nwindow_minutes: 10\nincident_threshold: 50\n"
      "labels: {}\n";  // flow mapping is rejected by the YAML subset
  EXPECT_EQ(bad(base), "yaml");
  const std::string ok =
      "version: 1\nwindow_minutes: 10\nincident_threshold: 50\nlabels:\n  low: 0\n  medium: 30\n"
      "  high: 60\n  critical: 80\nseverity_points:\n  low: 10\n  medium: 25\n  high: 40\n"
      "  critical: 60\n";
  EXPECT_EQ(bad(ok), "");
  EXPECT_NE(
      bad(ok + "correlations:\n  - id: c1\n    requires: [a]\n    bonus: 5\n").find("two or more"),
      std::string::npos);
  EXPECT_NE(bad(ok + "correlations:\n  - id: c1\n    requires: [a, b]\n").find("at least one"),
            std::string::npos);
  EXPECT_NE(bad(ok + "correlations:\n  - id: c1\n    requires: [a, b]\n    multiplier: 1.255\n")
                .find("two decimal"),
            std::string::npos);
  EXPECT_NE(bad("version: 2\n").find("version"), std::string::npos);
}

TEST(Rules, CorrelationMustReferenceKnownSignals) {
  const std::filesystem::path tmp = std::filesystem::temp_directory_path() / "edr_rules_test";
  std::filesystem::remove_all(tmp);
  std::filesystem::create_directories(tmp);
  {
    std::ofstream(tmp / "a.yaml")
        << "id: a1\ntitle: A\nseverity: low\nevent_types: "
           "[dns_query]\ncondition:\n  field: query_name\n  exists: true\n";
  }
  Scoring s = test::shipped_scoring();
  auto r = load_rules(tmp, s);
  ASSERT_TRUE(std::holds_alternative<ConfigError>(r));
  EXPECT_NE(std::get<ConfigError>(r).message.find("unknown signal"), std::string::npos);
  {
    std::ofstream(tmp / "b.yaml")
        << "id: a1\ntitle: B\nseverity: low\nevent_types: "
           "[dns_query]\ncondition:\n  field: query_name\n  exists: true\n";
  }
  s.correlations.clear();
  auto dup = load_rules(tmp, s);
  ASSERT_TRUE(std::holds_alternative<ConfigError>(dup));
  EXPECT_NE(std::get<ConfigError>(dup).message.find("duplicate"), std::string::npos);
  std::filesystem::remove_all(tmp);
}

}  // namespace
}  // namespace edr
