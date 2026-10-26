#include "edr/scorer.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "edr/condition.hpp"
#include "edr/encoded_command.hpp"
#include "edr/netutil.hpp"
#include "edr/textutil.hpp"

namespace edr {
namespace {

std::string detail_for(const Event& ev) {
  switch (ev.type) {
    case EventType::NetworkConnect:
      return ev.dest_ip + ":" + (ev.dest_port ? std::to_string(*ev.dest_port) : std::string());
    case EventType::DnsQuery:
      return ev.query_name;
    case EventType::ProcessAccess:
      return ev.target_image;
    case EventType::FileCreate:
    case EventType::FileDelete:
    case EventType::FileRename:
    case EventType::RegistryCreate:
    case EventType::RegistrySet:
    case EventType::RegistryDelete:
    case EventType::RegistryRename:
      return ev.target_path;
    default:
      return ev.image_name;
  }
}

// Multi-signal requirement: N distinct rule ids, unless a critical signal is present.
bool enough_signal_types(const std::vector<Signal>& signals, const Scoring& sc) {
  std::set<std::string> ids;
  for (const auto& s : signals) {
    if (s.severity == Severity::Critical) {
      return true;
    }
    ids.insert(s.rule_id);
  }
  return static_cast<int>(ids.size()) >= sc.incident_min_distinct;
}

bool correlation_fires(const Correlation& c, const std::vector<Signal>& signals) {
  std::vector<std::int64_t> times;
  std::optional<std::int64_t> last;
  for (const auto& req : c.requires_signals) {
    std::optional<std::int64_t> best;
    for (const auto& s : signals) {
      if (s.rule_id != req) {
        continue;
      }
      if (c.ordered && last && s.ts_ms < *last) {
        continue;
      }
      if (!best || s.ts_ms < *best) {
        best = s.ts_ms;
      }
    }
    if (!best) {
      return false;
    }
    last = best;
    times.push_back(*best);
  }
  const auto [lo, hi] = std::minmax_element(times.begin(), times.end());
  return *hi - *lo <= c.within_ms;
}

json::Value opt_int(const std::optional<std::int64_t>& v) {
  return v ? json::Value(*v) : json::Value(nullptr);
}

}  // namespace

std::string incident_id(const std::string& tree_key) {
  return "inc-" + fnv1a64(tree_key);
}

Engine::Engine(RuleSet rules, Scoring scoring, Baseline baseline)
    : rules_(std::move(rules)), scoring_(std::move(scoring)), baseline_(std::move(baseline)) {}

std::vector<Incident> Engine::process(Event event) {
  ++events_seen_;
  HostContext& hc = hosts_[event.host];
  hc.now_ms = std::max(hc.now_ms, event.ts_ms);
  expire(hc);
  update_processes(hc, event);
  enrich(hc, event);
  std::vector<Incident> updates;
  for (auto& sig : signals_for(event)) {
    ++signals_seen_;
    if (auto inc = add_signal(hc, event, std::move(sig))) {
      updates.push_back(std::move(*inc));
    }
  }
  return updates;
}

std::vector<Signal> Engine::match(Event event) {
  HostContext& hc = hosts_[event.host];
  hc.now_ms = std::max(hc.now_ms, event.ts_ms);
  update_processes(hc, event);
  enrich(hc, event);
  return signals_for(event);
}

void Engine::expire(HostContext& hc) {
  const std::int64_t cutoff = hc.now_ms - scoring_.window_ms;
  for (auto it = hc.trees.begin(); it != hc.trees.end();) {
    if (it->second.last_ms < cutoff) {
      closed_.push_back(std::move(it->second));
      it = hc.trees.erase(it);
    } else {
      ++it;
    }
  }
  if (closed_.size() > kMaxClosedTrees) {
    closed_.erase(closed_.begin(),
                  closed_.begin() + static_cast<std::ptrdiff_t>(closed_.size() - kMaxClosedTrees));
  }
  for (auto it = hc.processes.begin(); it != hc.processes.end();) {
    if (it->second.end_ms && *it->second.end_ms < cutoff) {
      it = hc.processes.erase(it);
    } else {
      ++it;
    }
  }
}

void Engine::update_processes(HostContext& hc, const Event& ev) {
  auto& procs = hc.processes;
  if (ev.type == EventType::ProcessCreate) {
    if (ev.ppid && procs.count(*ev.ppid) == 0 && !ev.parent_image.empty()) {
      procs[*ev.ppid] = ProcessNode{*ev.ppid, std::nullopt, ev.parent_image, ev.parent_command_line,
                                    0,        std::nullopt};
    }
    procs[ev.pid] = ProcessNode{ev.pid, ev.ppid, ev.image, ev.command_line, ev.ts_ms, std::nullopt};
  } else if (ev.type == EventType::ProcessTerminate) {
    auto it = procs.find(ev.pid);
    if (it != procs.end()) {
      it->second.end_ms = ev.ts_ms;
    } else {
      procs[ev.pid] = ProcessNode{ev.pid, std::nullopt, ev.image, "", 0, ev.ts_ms};
    }
  } else if (procs.count(ev.pid) == 0) {
    procs[ev.pid] = ProcessNode{ev.pid, std::nullopt, ev.image, "", 0, std::nullopt};
  }
  if (procs.size() > kMaxProcessesPerHost) {
    std::vector<std::pair<std::int64_t, std::int64_t>> order;  // (start, pid)
    order.reserve(procs.size());
    for (const auto& [pid, node] : procs) {
      order.emplace_back(node.start_ms, pid);
    }
    std::sort(order.begin(), order.end());
    const std::size_t extra = procs.size() - kMaxProcessesPerHost;
    for (std::size_t i = 0; i < extra; ++i) {
      procs.erase(order[i].second);
    }
  }
}

void Engine::enrich(const HostContext& hc, Event& ev) const {
  const auto& procs = hc.processes;
  ev.image_name = image_name(ev.image);
  const auto node = procs.find(ev.pid);
  std::optional<std::int64_t> ppid = ev.ppid;
  if (!ppid && node != procs.end()) {
    ppid = node->second.ppid;
  }
  if (ev.parent_image.empty() && ppid) {
    const auto parent = procs.find(*ppid);
    if (parent != procs.end()) {
      ev.parent_image = parent->second.image;
    }
  }
  if (!ev.parent_image.empty()) {
    ev.parent_image_name = image_name(ev.parent_image);
  }
  ev.ancestor_images.clear();
  ev.decoded_command.clear();
  ev.encoded_command_error.clear();
  std::optional<std::int64_t> cur = ppid;
  while (cur && ev.ancestor_images.size() < static_cast<std::size_t>(scoring_.max_depth)) {
    const auto it = procs.find(*cur);
    if (it == procs.end()) {
      break;
    }
    ev.ancestor_images.push_back(it->second.image);
    cur = it->second.ppid;
  }
  if (!ev.command_line.empty()) {
    DecodeResult res = decode_encoded_command(ev.command_line);
    if (res.text) {
      ev.decoded_command = std::move(*res.text);
    } else if (res.error) {
      ev.encoded_command_error = *res.error;
    }
  }
}

std::vector<Signal> Engine::signals_for(const Event& ev) {
  std::vector<Signal> out;
  const std::string detail = detail_for(ev);
  for (const Rule& rule : rules_.rules) {
    if (std::find(rule.event_types.begin(), rule.event_types.end(), ev.type) ==
        rule.event_types.end()) {
      continue;
    }
    if (evaluate(rule.condition, ev)) {
      out.push_back(Signal{rule.id, rule.title, rule.severity, rule.points, rule.attack, ev.ts_ms,
                           ev.pid, ev.image, ev.id, detail, 0, 0});
    }
  }
  const AnomalousOutbound& ao = scoring_.anomalous;
  if (ao.enabled && ev.type == EventType::NetworkConnect && (!ev.initiated || *ev.initiated)) {
    if (auto reason = anomalous_reason(ev)) {
      out.push_back(Signal{ao.id, ao.title, ao.severity, ao.points, ao.attack, ev.ts_ms, ev.pid,
                           ev.image, ev.id, *reason, 0, 0});
    }
  }
  return out;
}

std::optional<std::string> Engine::anomalous_reason(const Event& ev) {
  const AnomalousOutbound& ao = scoring_.anomalous;
  const auto ip = parse_ip(ev.dest_ip);
  if (!ip) {
    return std::nullopt;
  }
  const std::string where =
      ev.dest_ip + ":" + (ev.dest_port ? std::to_string(*ev.dest_port) : std::string());
  if (const Cidr* hit = ip_in_any(*ip, ao.untrusted)) {
    return where + " is in untrusted range " + hit->text;
  }
  if (ip_in_any(*ip, ao.trusted) != nullptr) {
    return std::nullopt;
  }
  BaselineKey key{ev.host, ev.image_name, ascii_lower(ev.dest_ip)};
  if (baseline_.count(key) != 0) {
    return std::nullopt;
  }
  if (ao.learn) {
    baseline_.insert(std::move(key));
  }
  return where + " not in baseline for " + ev.image_name;
}

const ProcessNode& Engine::root_of(const HostContext& hc, std::int64_t pid) const {
  const auto& procs = hc.processes;
  const ProcessNode* node = &procs.at(pid);
  int depth = 0;
  while (depth < scoring_.max_depth) {
    if (!node->ppid) {
      break;
    }
    const auto parent = procs.find(*node->ppid);
    if (parent == procs.end() ||
        scoring_.boundary_images.count(image_name(parent->second.image)) != 0) {
      break;
    }
    if (parent->second.pid == node->pid) {
      break;
    }
    node = &parent->second;
    ++depth;
  }
  return *node;
}

std::optional<Incident> Engine::add_signal(HostContext& hc, const Event& ev, Signal sig) {
  const ProcessNode& root = root_of(hc, sig.pid);
  const std::string key =
      ev.host + "|" + std::to_string(root.pid) + "|" + std::to_string(root.start_ms);
  auto it = hc.trees.find(key);
  if (it == hc.trees.end()) {
    Tree t;
    t.key = key;
    t.seq = ++seq_;
    t.host = ev.host;
    t.root_pid = root.pid;
    t.root_image = root.image;
    t.root_start_ms = root.start_ms;
    it = hc.trees.emplace(key, std::move(t)).first;
  }
  Tree& tree = it->second;
  const std::int64_t cutoff = sig.ts_ms - scoring_.window_ms;
  tree.signals.erase(std::remove_if(tree.signals.begin(), tree.signals.end(),
                                    [&](const Signal& s) { return s.ts_ms < cutoff; }),
                     tree.signals.end());
  const auto repeat =
      static_cast<int>(std::count_if(tree.signals.begin(), tree.signals.end(),
                                     [&](const Signal& s) { return s.rule_id == sig.rule_id; }));
  int points = sig.base_points;
  if (repeat >= scoring_.max_counted) {
    points = 0;
  } else {
    for (int i = 0; i < repeat; ++i) {
      points = points * scoring_.decay_percent / 100;
    }
  }
  sig.points = points;
  sig.repeat = repeat;
  tree.last_ms = std::max(tree.last_ms, sig.ts_ms);
  tree.signals.push_back(std::move(sig));
  ++tree.total_signals;
  const bool have = std::any_of(tree.evidence.begin(), tree.evidence.end(),
                                [&](const auto& e) { return e.first == ev.id; });
  if (!have) {
    tree.evidence.emplace_back(ev.id, ev);
  }

  ScoreResult sr = score(tree.signals);
  tree.best_score = std::max(tree.best_score, sr.score);
  if (sr.score < scoring_.incident_threshold || !enough_signal_types(tree.signals, scoring_)) {
    return std::nullopt;
  }
  if (tree.incident && sr.score < tree.incident->score) {
    return std::nullopt;
  }
  ++tree.version;
  tree.incident = make_incident(hc, tree, sr);
  return tree.incident;
}

ScoreResult Engine::score(const std::vector<Signal>& signals) const {
  ScoreResult r;
  int low_total = 0;
  int other = 0;
  for (const auto& s : signals) {
    BreakdownItem b;
    b.kind = "signal";
    b.rule_id = s.rule_id;
    b.label = s.title;
    b.detail = s.detail;
    b.points = s.points;
    r.breakdown.push_back(std::move(b));
    if (s.severity == Severity::Low) {
      low_total += s.points;
    } else {
      other += s.points;
    }
  }
  const int low_counted = std::min(low_total, scoring_.low_severity_cap);
  if (low_counted < low_total) {
    BreakdownItem b;
    b.kind = "low_cap";
    b.label = "low-severity signals capped at " + std::to_string(scoring_.low_severity_cap);
    b.points = low_counted - low_total;
    r.breakdown.push_back(std::move(b));
  }
  int score = other + low_counted;
  for (const auto& c : scoring_.correlations) {
    if (correlation_fires(c, signals)) {
      r.fired.push_back(&c);
    }
  }
  for (const Correlation* c : r.fired) {
    if (c->multiplier_percent != 100) {
      BreakdownItem b;
      b.kind = "multiplier";
      b.correlation = c->id;
      b.label = c->title;
      b.multiplier_percent = c->multiplier_percent;
      b.before = score;
      score = (score * c->multiplier_percent + 50) / 100;
      b.after = score;
      r.breakdown.push_back(std::move(b));
    }
    if (c->bonus != 0) {
      score += c->bonus;
      BreakdownItem b;
      b.kind = "bonus";
      b.correlation = c->id;
      b.label = c->title;
      b.points = c->bonus;
      b.after = score;
      r.breakdown.push_back(std::move(b));
    }
  }
  const Correlation* floor_corr = nullptr;
  for (const Correlation* c : r.fired) {
    if (c->min_score != 0 && (floor_corr == nullptr || c->min_score > floor_corr->min_score)) {
      floor_corr = c;
    }
  }
  if (floor_corr != nullptr && score < floor_corr->min_score) {
    score = floor_corr->min_score;
    BreakdownItem b;
    b.kind = "floor";
    b.correlation = floor_corr->id;
    b.label = floor_corr->title;
    b.after = score;
    r.breakdown.push_back(std::move(b));
  }
  if (score > 100) {
    score = 100;
    BreakdownItem b;
    b.kind = "cap";
    b.label = "score capped at 100";
    b.after = 100;
    r.breakdown.push_back(std::move(b));
  }
  r.score = score;
  r.label = scoring_.label_for(score);
  return r;
}

Incident Engine::make_incident(const HostContext& hc, const Tree& tree,
                               const ScoreResult& sr) const {
  Incident inc;
  inc.id = incident_id(tree.key);
  inc.version = tree.version;
  inc.host = tree.host;
  inc.score = sr.score;
  inc.label = sr.label;
  inc.root_pid = tree.root_pid;
  inc.root_image = tree.root_image;
  inc.root_start_ms = tree.root_start_ms;
  inc.signals = tree.signals;
  inc.first_ms = tree.signals.front().ts_ms;
  inc.last_ms = tree.signals.front().ts_ms;
  std::set<std::string> attack;
  std::vector<std::string> evidence_ids;
  for (const auto& s : tree.signals) {
    inc.first_ms = std::min(inc.first_ms, s.ts_ms);
    inc.last_ms = std::max(inc.last_ms, s.ts_ms);
    attack.insert(s.attack.begin(), s.attack.end());
    if (std::find(evidence_ids.begin(), evidence_ids.end(), s.event_id) == evidence_ids.end()) {
      evidence_ids.push_back(s.event_id);
    }
  }
  inc.attack.assign(attack.begin(), attack.end());
  for (const Correlation* c : sr.fired) {
    inc.correlations.push_back(*c);
  }
  inc.breakdown = sr.breakdown;
  for (std::size_t i = 0; i < evidence_ids.size() && i < kMaxEvidence; ++i) {
    for (const auto& [id, ev] : tree.evidence) {
      if (id == evidence_ids[i]) {
        inc.evidence.push_back(ev);
        break;
      }
    }
  }

  // Process tree excerpt: every signal's chain up to the root, root at depth 0.
  const auto& procs = hc.processes;
  std::vector<std::pair<std::int64_t, int>> chosen;  // (pid, depth), first assignment wins
  auto choose = [&](std::int64_t pid, int depth) {
    for (const auto& c : chosen) {
      if (c.first == pid) {
        return;
      }
    }
    chosen.emplace_back(pid, depth);
  };
  for (const auto& s : tree.signals) {
    std::vector<std::int64_t> chain;
    std::optional<std::int64_t> cur = s.pid;
    while (cur && procs.count(*cur) != 0 &&
           chain.size() <= static_cast<std::size_t>(scoring_.max_depth)) {
      chain.push_back(*cur);
      if (*cur == tree.root_pid) {
        break;
      }
      cur = procs.at(*cur).ppid;
    }
    if (!chain.empty() && chain.back() == tree.root_pid) {
      int depth = 0;
      for (auto pit = chain.rbegin(); pit != chain.rend(); ++pit) {
        choose(*pit, depth++);
      }
    } else if (procs.count(s.pid) != 0) {
      choose(s.pid, 1);
    }
  }
  for (const auto& [pid, depth] : chosen) {
    const ProcessNode& n = procs.at(pid);
    inc.process_tree.push_back(
        TreeNodeView{n.pid, n.ppid, n.image, n.command_line, n.start_ms, depth});
  }
  std::sort(inc.process_tree.begin(), inc.process_tree.end(),
            [](const TreeNodeView& a, const TreeNodeView& b) {
              return std::tie(a.depth, a.start_ms, a.pid) < std::tie(b.depth, b.start_ms, b.pid);
            });
  if (inc.process_tree.size() > kMaxTreeNodes) {
    inc.process_tree.resize(kMaxTreeNodes);
  }
  return inc;
}

std::vector<const Tree*> Engine::all_trees() const {
  // Ordered by creation sequence number (deterministic, independent of addresses).
  std::vector<std::pair<std::uint64_t, const Tree*>> order;
  order.reserve(closed_.size());
  for (const auto& t : closed_) {
    order.emplace_back(t.seq, &t);
  }
  for (const auto& [host, hc] : hosts_) {
    for (const auto& [key, t] : hc.trees) {
      order.emplace_back(t.seq, &t);
    }
  }
  std::sort(order.begin(), order.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });
  std::vector<const Tree*> out;
  out.reserve(order.size());
  for (const auto& entry : order) {
    out.push_back(entry.second);
  }
  return out;
}

std::vector<TreeSummary> Engine::tree_summaries() const {
  std::vector<TreeSummary> out;
  for (const Tree* t : all_trees()) {
    TreeSummary s;
    s.host = t->host;
    s.root_pid = t->root_pid;
    s.root_image = t->root_image;
    s.score = t->best_score;
    s.label = scoring_.label_for(t->best_score);
    s.signals = t->total_signals;
    if (t->incident) {
      s.incident_id = t->incident->id;
    }
    out.push_back(std::move(s));
  }
  return out;
}

std::vector<Incident> Engine::incidents() const {
  std::vector<Incident> out;
  for (const Tree* t : all_trees()) {
    if (t->incident) {
      out.push_back(*t->incident);
    }
  }
  return out;
}

json::Value incident_to_json(const Incident& inc) {
  json::Object o;
  o.emplace_back("kind", "incident");
  o.emplace_back("id", inc.id);
  o.emplace_back("version", static_cast<std::int64_t>(inc.version));
  o.emplace_back("host", inc.host);
  o.emplace_back("score", static_cast<std::int64_t>(inc.score));
  o.emplace_back("label", inc.label);
  o.emplace_back("first_seen", format_ts(inc.first_ms));
  o.emplace_back("last_seen", format_ts(inc.last_ms));
  json::Object root;
  root.emplace_back("pid", inc.root_pid);
  root.emplace_back("image", inc.root_image);
  root.emplace_back("start", inc.root_start_ms != 0 ? json::Value(format_ts(inc.root_start_ms))
                                                    : json::Value(nullptr));
  o.emplace_back("root", json::Value(std::move(root)));
  json::Array signals;
  for (const auto& s : inc.signals) {
    json::Object so;
    so.emplace_back("rule_id", s.rule_id);
    so.emplace_back("title", s.title);
    so.emplace_back("severity", std::string(to_string(s.severity)));
    so.emplace_back("points", static_cast<std::int64_t>(s.points));
    so.emplace_back("base_points", static_cast<std::int64_t>(s.base_points));
    so.emplace_back("repeat", static_cast<std::int64_t>(s.repeat));
    so.emplace_back("ts", format_ts(s.ts_ms));
    so.emplace_back("pid", s.pid);
    so.emplace_back("image", s.image);
    so.emplace_back("event_id", s.event_id);
    so.emplace_back("detail", s.detail);
    json::Array attack;
    for (const auto& a : s.attack) {
      attack.emplace_back(a);
    }
    so.emplace_back("attack", json::Value(std::move(attack)));
    signals.emplace_back(std::move(so));
  }
  o.emplace_back("signals", json::Value(std::move(signals)));
  json::Array corrs;
  for (const auto& c : inc.correlations) {
    json::Object co;
    co.emplace_back("id", c.id);
    co.emplace_back("title", c.title);
    co.emplace_back("multiplier_percent", static_cast<std::int64_t>(c.multiplier_percent));
    co.emplace_back("bonus", static_cast<std::int64_t>(c.bonus));
    co.emplace_back("min_score", static_cast<std::int64_t>(c.min_score));
    corrs.emplace_back(std::move(co));
  }
  o.emplace_back("correlations", json::Value(std::move(corrs)));
  json::Array breakdown;
  for (const auto& b : inc.breakdown) {
    json::Object bo;
    bo.emplace_back("kind", b.kind);
    if (b.kind == "signal") {
      bo.emplace_back("rule_id", b.rule_id);
      bo.emplace_back("label", b.label);
      bo.emplace_back("detail", b.detail);
      bo.emplace_back("points", static_cast<std::int64_t>(b.points));
    } else if (b.kind == "low_cap") {
      bo.emplace_back("label", b.label);
      bo.emplace_back("points", static_cast<std::int64_t>(b.points));
    } else if (b.kind == "multiplier") {
      bo.emplace_back("correlation", b.correlation);
      bo.emplace_back("label", b.label);
      bo.emplace_back("multiplier_percent", static_cast<std::int64_t>(b.multiplier_percent));
      bo.emplace_back("before", static_cast<std::int64_t>(b.before));
      bo.emplace_back("after", static_cast<std::int64_t>(b.after));
    } else if (b.kind == "bonus") {
      bo.emplace_back("correlation", b.correlation);
      bo.emplace_back("label", b.label);
      bo.emplace_back("points", static_cast<std::int64_t>(b.points));
      bo.emplace_back("after", static_cast<std::int64_t>(b.after));
    } else if (b.kind == "floor") {
      bo.emplace_back("correlation", b.correlation);
      bo.emplace_back("label", b.label);
      bo.emplace_back("after", static_cast<std::int64_t>(b.after));
    } else {
      bo.emplace_back("label", b.label);
      bo.emplace_back("after", static_cast<std::int64_t>(b.after));
    }
    breakdown.emplace_back(std::move(bo));
  }
  o.emplace_back("breakdown", json::Value(std::move(breakdown)));
  json::Array attack;
  for (const auto& a : inc.attack) {
    attack.emplace_back(a);
  }
  o.emplace_back("attack", json::Value(std::move(attack)));
  json::Array tree;
  for (const auto& n : inc.process_tree) {
    json::Object no;
    no.emplace_back("pid", n.pid);
    no.emplace_back("ppid", opt_int(n.ppid));
    no.emplace_back("image", n.image);
    no.emplace_back("command_line", n.command_line);
    no.emplace_back("start",
                    n.start_ms != 0 ? json::Value(format_ts(n.start_ms)) : json::Value(nullptr));
    no.emplace_back("depth", static_cast<std::int64_t>(n.depth));
    tree.emplace_back(std::move(no));
  }
  o.emplace_back("process_tree", json::Value(std::move(tree)));
  json::Array evidence;
  for (const auto& ev : inc.evidence) {
    evidence.push_back(event_to_json(ev));
  }
  o.emplace_back("evidence", json::Value(std::move(evidence)));
  return json::Value(std::move(o));
}

json::Value tree_summary_to_json(const TreeSummary& s) {
  json::Object o;
  o.emplace_back("kind", "tree");
  o.emplace_back("host", s.host);
  o.emplace_back("root_pid", s.root_pid);
  o.emplace_back("root_image", s.root_image);
  o.emplace_back("score", static_cast<std::int64_t>(s.score));
  o.emplace_back("label", s.label);
  o.emplace_back("signals", static_cast<std::int64_t>(s.signals));
  o.emplace_back("incident_id", s.incident_id ? json::Value(*s.incident_id) : json::Value(nullptr));
  return json::Value(std::move(o));
}

}  // namespace edr
