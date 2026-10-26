#pragma once

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include "edr/event.hpp"
#include "edr/json.hpp"
#include "edr/rules.hpp"
#include "edr/scorer.hpp"
#include "edr/textutil.hpp"

namespace edr::test {

inline std::filesystem::path repo() {
  return EDR_REPO_DIR;
}
inline std::filesystem::path test_dir() {
  return EDR_TEST_DIR;
}

inline std::string read_text(const std::filesystem::path& p) {
  std::ifstream in(p, std::ios::binary);
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

inline json::Value parse_json(const std::string& text) {
  auto v = json::parse(text);
  if (auto* e = std::get_if<json::ParseError>(&v)) {
    ADD_FAILURE() << "JSON error: " << e->message << " in " << text.substr(0, 200);
    return json::Value();
  }
  return std::get<json::Value>(v);
}

inline Event make_event(const json::Value& v) {
  auto ev = event_from_json(v);
  if (auto* e = std::get_if<EventParseError>(&ev)) {
    ADD_FAILURE() << "event error: " << e->message;
    return Event{};
  }
  return std::get<Event>(ev);
}

inline Event make_event_text(const std::string& json_text) {
  return make_event(parse_json(json_text));
}

inline std::vector<Event> read_events(const std::filesystem::path& p) {
  std::vector<Event> out;
  std::istringstream in(read_text(p));
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty()) {
      out.push_back(make_event_text(line));
    }
  }
  return out;
}

inline Scoring shipped_scoring() {
  auto s = load_scoring(repo() / "rules" / "scoring.yaml");
  if (auto* e = std::get_if<ConfigError>(&s)) {
    ADD_FAILURE() << e->message;
    return Scoring{};
  }
  return std::get<Scoring>(s);
}

inline RuleSet shipped_rules(const Scoring& scoring) {
  auto r = load_rules(repo() / "rules" / "detections", scoring);
  if (auto* e = std::get_if<ConfigError>(&r)) {
    ADD_FAILURE() << e->message;
    return RuleSet{};
  }
  return std::get<RuleSet>(r);
}

inline Baseline sample_baseline() {
  auto b = load_baseline(repo() / "samples" / "baseline.json");
  if (auto* e = std::get_if<ConfigError>(&b)) {
    ADD_FAILURE() << e->message;
    return Baseline{};
  }
  return std::get<Baseline>(b);
}

inline Engine shipped_engine(bool with_baseline = true) {
  Scoring s = shipped_scoring();
  RuleSet r = shipped_rules(s);
  return Engine(std::move(r), std::move(s), with_baseline ? sample_baseline() : Baseline{});
}

}  // namespace edr::test
