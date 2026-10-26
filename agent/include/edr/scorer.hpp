// Process-tree context, rule evaluation and multi-signal risk scoring.
//
// The algorithm (documented in docs/scoring.md) is identical to
// server/src/edr_server/engine/scorer.py; server/tests/test_parity.py checks that both produce
// the same incidents and tree scores for every sample scenario.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "edr/event.hpp"
#include "edr/json.hpp"
#include "edr/rules.hpp"

namespace edr {

inline constexpr std::size_t kMaxProcessesPerHost = 50000;
inline constexpr std::size_t kMaxEvidence = 25;
inline constexpr std::size_t kMaxTreeNodes = 50;
inline constexpr std::size_t kMaxClosedTrees = 1000;

struct Signal {
  std::string rule_id;
  std::string title;
  Severity severity = Severity::Low;
  int base_points = 0;
  std::vector<std::string> attack;
  std::int64_t ts_ms = 0;
  std::int64_t pid = 0;
  std::string image;
  std::string event_id;
  std::string detail;
  int points = 0;
  int repeat = 0;
};

struct BreakdownItem {
  std::string kind;  // signal | low_cap | multiplier | bonus | floor | cap
  std::string rule_id;
  std::string correlation;
  std::string label;
  std::string detail;
  int points = 0;
  int multiplier_percent = 0;
  int before = 0;
  int after = 0;
};

struct ProcessNode {
  std::int64_t pid = 0;
  std::optional<std::int64_t> ppid;
  std::string image;
  std::string command_line;
  std::int64_t start_ms = 0;  // 0 for stubs
  std::optional<std::int64_t> end_ms;
};

struct TreeNodeView {
  std::int64_t pid = 0;
  std::optional<std::int64_t> ppid;
  std::string image;
  std::string command_line;
  std::int64_t start_ms = 0;
  int depth = 0;
};

struct Incident {
  std::string id;
  int version = 0;
  std::string host;
  int score = 0;
  std::string label;
  std::int64_t first_ms = 0;
  std::int64_t last_ms = 0;
  std::int64_t root_pid = 0;
  std::string root_image;
  std::int64_t root_start_ms = 0;
  std::vector<Signal> signals;
  std::vector<Correlation> correlations;
  std::vector<BreakdownItem> breakdown;
  std::vector<std::string> attack;
  std::vector<TreeNodeView> process_tree;
  std::vector<Event> evidence;
};

struct ScoreResult {
  int score = 0;
  std::string label;
  std::vector<BreakdownItem> breakdown;
  std::vector<const Correlation*> fired;
};

struct Tree {
  std::string key;
  std::uint64_t seq = 0;
  std::string host;
  std::int64_t root_pid = 0;
  std::string root_image;
  std::int64_t root_start_ms = 0;
  std::vector<Signal> signals;
  std::vector<std::pair<std::string, Event>> evidence;  // insertion order, unique by id
  std::int64_t last_ms = 0;
  int best_score = 0;
  int version = 0;
  std::optional<Incident> incident;
  int total_signals = 0;
};

struct TreeSummary {
  std::string host;
  std::int64_t root_pid = 0;
  std::string root_image;
  int score = 0;
  std::string label;
  int signals = 0;
  std::optional<std::string> incident_id;
};

class Engine {
 public:
  Engine(RuleSet rules, Scoring scoring, Baseline baseline = {});

  // Feeds one normalized event; returns new incident versions (possibly none).
  std::vector<Incident> process(Event event);
  // Runs steps 1-4 (process table, enrichment, rule evaluation) without scoring and returns the
  // signals the event produces. Used by the per-rule tests.
  std::vector<Signal> match(Event event);

  [[nodiscard]] std::vector<TreeSummary> tree_summaries() const;
  // Latest version of every incident, in tree creation order.
  [[nodiscard]] std::vector<Incident> incidents() const;
  [[nodiscard]] ScoreResult score(const std::vector<Signal>& signals) const;

  [[nodiscard]] const Scoring& scoring() const { return scoring_; }
  [[nodiscard]] const RuleSet& rules() const { return rules_; }
  [[nodiscard]] std::uint64_t events_seen() const { return events_seen_; }
  [[nodiscard]] std::uint64_t signals_seen() const { return signals_seen_; }
  [[nodiscard]] std::size_t baseline_size() const { return baseline_.size(); }

 private:
  struct HostContext {
    std::int64_t now_ms = 0;
    std::unordered_map<std::int64_t, ProcessNode> processes;
    std::map<std::string, Tree> trees;
  };

  void expire(HostContext& hc);
  static void update_processes(HostContext& hc, const Event& ev);
  void enrich(const HostContext& hc, Event& ev) const;
  std::vector<Signal> signals_for(const Event& ev);
  std::optional<std::string> anomalous_reason(const Event& ev);
  const ProcessNode& root_of(const HostContext& hc, std::int64_t pid) const;
  std::optional<Incident> add_signal(HostContext& hc, const Event& ev, Signal sig);
  Incident make_incident(const HostContext& hc, const Tree& tree, const ScoreResult& sr) const;
  [[nodiscard]] std::vector<const Tree*> all_trees() const;

  RuleSet rules_;
  Scoring scoring_;
  Baseline baseline_;
  std::map<std::string, HostContext> hosts_;
  std::vector<Tree> closed_;
  std::uint64_t seq_ = 0;
  std::uint64_t events_seen_ = 0;
  std::uint64_t signals_seen_ = 0;
};

std::string incident_id(const std::string& tree_key);
json::Value incident_to_json(const Incident& incident);
json::Value tree_summary_to_json(const TreeSummary& summary);

}  // namespace edr
