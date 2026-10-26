#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "edr/scorer.hpp"
#include "edr/textutil.hpp"
#include "test_util.hpp"

namespace edr {
namespace {

constexpr const char* kPs = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
constexpr const char* kDemo = "aABpAA==";  // "hi" as UTF-16LE

std::int64_t t0() {
  return *parse_ts("2026-10-20T10:00:00Z");
}

Event proc(int sec, std::int64_t pid, std::int64_t ppid, const std::string& image,
           const std::string& cmd, const std::string& host = "WS-T") {
  Event e;
  e.id = "p-" + std::to_string(pid) + "-" + std::to_string(sec);
  e.ts_ms = t0() + sec * 1000LL;
  e.host = host;
  e.type = EventType::ProcessCreate;
  e.pid = pid;
  e.ppid = ppid;
  e.image = image;
  e.command_line = cmd;
  return e;
}

Event net(int sec, std::int64_t pid, const std::string& image, const std::string& ip, int port,
          const std::string& host = "WS-T") {
  Event e;
  e.id = "n-" + std::to_string(pid) + "-" + std::to_string(sec) + "-" + ip;
  e.ts_ms = t0() + sec * 1000LL;
  e.host = host;
  e.type = EventType::NetworkConnect;
  e.pid = pid;
  e.image = image;
  e.dest_ip = ip;
  e.dest_port = port;
  e.initiated = true;
  return e;
}

Event encoded_ps(int sec, std::int64_t pid, std::int64_t ppid) {
  return proc(sec, pid, ppid, kPs, std::string("powershell.exe -enc ") + kDemo);
}

TEST(Scorer, SingleHitStaysASignalNotAnIncident) {
  Engine engine = test::shipped_engine(false);
  EXPECT_TRUE(engine.process(encoded_ps(0, 200, 100)).empty());
  EXPECT_TRUE(engine.incidents().empty());
  const auto trees = engine.tree_summaries();
  ASSERT_EQ(trees.size(), 1U);
  EXPECT_EQ(trees[0].score, 40);
  EXPECT_EQ(trees[0].label, "medium");
  EXPECT_FALSE(trees[0].incident_id.has_value());
}

TEST(Scorer, EncodedPowerShellPlusUnbaselinedOutboundBecomesAnIncident) {
  Engine engine = test::shipped_engine(false);
  engine.process(encoded_ps(0, 200, 100));
  const auto updates = engine.process(net(5, 200, kPs, "203.0.113.50", 443));
  ASSERT_EQ(updates.size(), 1U);
  const Incident& inc = updates[0];
  EXPECT_EQ(inc.score, 100);
  EXPECT_EQ(inc.label, "critical");
  ASSERT_EQ(inc.signals.size(), 2U);
  EXPECT_EQ(inc.signals[0].rule_id, "encoded-powershell");
  EXPECT_EQ(inc.signals[0].points, 40);
  EXPECT_EQ(inc.signals[1].rule_id, "anomalous-outbound");
  EXPECT_EQ(inc.signals[1].points, 35);
  EXPECT_EQ(inc.signals[1].detail, "203.0.113.50:443 not in baseline for powershell.exe");
  ASSERT_EQ(inc.correlations.size(), 1U);
  EXPECT_EQ(inc.correlations[0].id, "encoded-ps-then-network");
  // Breakdown: +40, +35, x1.5 (75 -> 113), cap at 100.
  ASSERT_EQ(inc.breakdown.size(), 4U);
  EXPECT_EQ(inc.breakdown[2].kind, "multiplier");
  EXPECT_EQ(inc.breakdown[2].before, 75);
  EXPECT_EQ(inc.breakdown[2].after, 113);
  EXPECT_EQ(inc.breakdown[3].kind, "cap");
  EXPECT_EQ(inc.process_tree.size(), 1U);
  EXPECT_EQ(inc.evidence.size(), 2U);
  EXPECT_EQ(inc.evidence[0].decoded_command, "hi");
}

TEST(Scorer, WithoutCorrelationTheSameSignalsScoreLower) {
  Scoring s = test::shipped_scoring();
  s.correlations.clear();
  RuleSet r = test::shipped_rules(test::shipped_scoring());
  Engine engine(std::move(r), std::move(s));
  engine.process(encoded_ps(0, 200, 100));
  const auto updates = engine.process(net(5, 200, kPs, "203.0.113.50", 443));
  ASSERT_EQ(updates.size(), 1U);
  EXPECT_EQ(updates[0].score, 75);
  EXPECT_EQ(updates[0].label, "high");
}

TEST(Scorer, CorrelationNeedsTheSameProcessTree) {
  Engine engine = test::shipped_engine(false);
  engine.process(encoded_ps(0, 200, 100));
  // An unrelated browser (its own tree) connects out.
  engine.process(net(5, 300, "C:\\Apps\\browser.exe", "203.0.113.50", 443));
  EXPECT_TRUE(engine.incidents().empty());
  EXPECT_EQ(engine.tree_summaries().size(), 2U);
}

TEST(Scorer, ChildProcessesShareTheTree) {
  Engine engine = test::shipped_engine(false);
  engine.process(proc(0, 150, 1, "C:\\Office\\WINWORD.EXE", "winword"));
  engine.process(encoded_ps(1, 200, 150));
  engine.process(proc(2, 210, 200, "C:\\Windows\\System32\\curl.exe", "curl"));
  const auto updates =
      engine.process(net(3, 210, "C:\\Windows\\System32\\curl.exe", "203.0.113.50", 443));
  ASSERT_EQ(updates.size(), 1U);
  EXPECT_EQ(updates[0].root_pid, 150);
  ASSERT_EQ(updates[0].process_tree.size(), 3U);
  EXPECT_EQ(updates[0].process_tree[0].pid, 150);
  EXPECT_EQ(updates[0].process_tree[0].depth, 0);
  EXPECT_EQ(updates[0].process_tree[2].pid, 210);
  EXPECT_EQ(updates[0].process_tree[2].depth, 2);
}

TEST(Scorer, BoundaryImagesSplitTrees) {
  Engine engine = test::shipped_engine(false);
  engine.process(proc(0, 50, 1, "C:\\Windows\\explorer.exe", "explorer"));
  engine.process(encoded_ps(1, 200, 50));
  engine.process(proc(2, 300, 50, "C:\\Apps\\tool.exe", "tool"));
  engine.process(net(3, 300, "C:\\Apps\\tool.exe", "203.0.113.50", 443));
  EXPECT_TRUE(engine.incidents().empty());  // explorer.exe is a boundary: two trees
}

TEST(Scorer, ContextWindowExpiry) {
  Engine engine = test::shipped_engine(false);
  engine.process(encoded_ps(0, 200, 100));
  // 11 minutes later: the encoded-PowerShell signal is outside the 10-minute window.
  EXPECT_TRUE(engine.process(net(11 * 60, 200, kPs, "203.0.113.50", 443)).empty());
  const auto trees = engine.tree_summaries();
  ASSERT_EQ(trees.size(), 2U);  // the first tree was closed, a new one opened
  EXPECT_EQ(trees[0].score, 40);
  EXPECT_EQ(trees[1].score, 35);
  // Just inside the window it still correlates.
  Engine fresh = test::shipped_engine(false);
  fresh.process(encoded_ps(0, 200, 100));
  EXPECT_EQ(fresh.process(net(9 * 60 + 59, 200, kPs, "203.0.113.50", 443)).size(), 1U);
}

TEST(Scorer, OrderedCorrelationIgnoresTheReverseOrder) {
  Engine engine = test::shipped_engine(false);
  engine.process(proc(0, 200, 100, kPs, "powershell.exe -NoProfile"));
  engine.process(net(1, 200, kPs, "203.0.113.50", 443));
  engine.process(proc(2, 210, 200, kPs, std::string("powershell -enc ") + kDemo));
  const auto trees = engine.tree_summaries();
  ASSERT_EQ(trees.size(), 1U);
  EXPECT_EQ(trees[0].score, 75);  // 35 + 40, no x1.5: the network came first
}

TEST(Scorer, BaselineTrustedRangesAndLearning) {
  Baseline b{{"WS-T", "browser.exe", "198.51.100.20"}};
  Scoring s = test::shipped_scoring();
  Engine engine(test::shipped_rules(s), s, b);
  const char* br = "C:\\Apps\\browser.exe";
  EXPECT_TRUE(engine.match(net(0, 1, br, "198.51.100.20", 443)).empty());   // baselined
  EXPECT_TRUE(engine.match(net(1, 1, br, "10.1.2.3", 443)).empty());        // trusted range
  EXPECT_EQ(engine.match(net(2, 1, br, "198.51.100.21", 443)).size(), 1U);  // new pair
  EXPECT_TRUE(engine.match(net(3, 1, br, "198.51.100.21", 443)).empty());   // learned
  const auto untrusted = engine.match(net(4, 1, br, "192.0.2.80", 80));
  ASSERT_EQ(untrusted.size(), 1U);
  EXPECT_EQ(untrusted[0].detail, "192.0.2.80:80 is in untrusted range 192.0.2.0/24");
  EXPECT_EQ(engine.match(net(5, 1, br, "192.0.2.80", 80)).size(), 1U);  // never learned
  Event inbound = net(6, 1, br, "198.51.100.99", 443);
  inbound.initiated = false;
  EXPECT_TRUE(engine.match(inbound).empty());
}

TEST(Scorer, RepeatsDecayAndStopCounting) {
  Engine engine = test::shipped_engine(false);
  engine.process(proc(0, 100, 1, "C:\\Windows\\System32\\cmd.exe", "cmd"));
  for (int i = 0; i < 5; ++i) {
    engine.process(proc(1 + i, 200 + i, 100, "C:\\Windows\\System32\\whoami.exe", "whoami"));
  }
  const auto trees = engine.tree_summaries();
  ASSERT_EQ(trees.size(), 1U);
  EXPECT_EQ(trees[0].score, 17);  // 10 + 5 + 2 + 0 + 0
  EXPECT_EQ(trees[0].signals, 5);
}

TEST(Scorer, LowSeverityCapLimitsNoise) {
  Engine engine = test::shipped_engine(false);
  const std::string temp = "C:\\Users\\u\\AppData\\Local\\Temp\\x\\";
  engine.process(proc(0, 100, 1, temp + "a.exe", "a"));  // exec-from-user-temp 10
  engine.process(proc(1, 101, 100, "C:\\Windows\\System32\\whoami.exe", "whoami"));  // 10
  engine.process(proc(2, 102, 100, "C:\\Windows\\System32\\quser.exe", "quser"));    // 5
  Event dns;
  dns.id = "d1";
  dns.ts_ms = t0() + 3000;
  dns.host = "WS-T";
  dns.type = EventType::DnsQuery;
  dns.pid = 100;
  dns.image = temp + "a.exe";
  dns.query_name = "a8f3kq9z7x2m4v1b.example.net";  // dns-high-entropy 10
  engine.process(dns);
  const auto trees = engine.tree_summaries();
  ASSERT_EQ(trees.size(), 1U);
  EXPECT_EQ(trees[0].signals, 4);
  EXPECT_EQ(trees[0].score, 20);  // 35 points of low-severity signals, capped at 20
  EXPECT_EQ(trees[0].label, "low");
  const ScoreResult sr =
      engine.score({Signal{"a", "A", Severity::Low, 10, {}, 0, 1, "", "e", "", 10, 0},
                    Signal{"b", "B", Severity::Low, 10, {}, 0, 1, "", "e", "", 15, 0}});
  ASSERT_EQ(sr.breakdown.size(), 3U);
  EXPECT_EQ(sr.breakdown[2].kind, "low_cap");
  EXPECT_EQ(sr.breakdown[2].points, -5);
}

TEST(Scorer, BonusAndFloorCorrelations) {
  Engine engine = test::shipped_engine(false);
  const std::string exe = "C:\\Users\\c\\AppData\\Local\\Temp\\7z\\helper.exe";
  engine.process(proc(0, 600, 1, exe, "helper"));
  Event reg;
  reg.id = "r1";
  reg.ts_ms = t0() + 2000;
  reg.host = "WS-T";
  reg.type = EventType::RegistrySet;
  reg.pid = 600;
  reg.image = exe;
  reg.target_path = "HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Helper";
  const auto updates = engine.process(reg);
  ASSERT_EQ(updates.size(), 1U);
  EXPECT_EQ(updates[0].score, 55);  // 10 + 30 + 15 bonus
  EXPECT_EQ(updates[0].label, "medium");
  EXPECT_EQ(updates[0].breakdown.back().kind, "bonus");

  Scoring s = test::shipped_scoring();
  Correlation c;
  c.id = "floor-demo";
  c.title = "floor";
  c.requires_signals = {"exec-from-user-temp", "discovery-commands"};
  c.within_ms = 600000;
  c.min_score = 70;
  s.correlations.push_back(c);
  Engine floor_engine(test::shipped_rules(test::shipped_scoring()), s);
  floor_engine.process(proc(0, 700, 1, exe, "helper"));
  const auto f =
      floor_engine.process(proc(1, 701, 700, "C:\\Windows\\System32\\whoami.exe", "whoami"));
  ASSERT_EQ(f.size(), 1U);
  EXPECT_EQ(f[0].score, 70);
  EXPECT_EQ(f[0].breakdown.back().kind, "floor");
}

TEST(Scorer, IncidentVersionsAndStableIds) {
  Engine engine = test::shipped_engine(false);
  engine.process(encoded_ps(0, 200, 100));
  const auto v1 = engine.process(net(1, 200, kPs, "203.0.113.50", 443));
  const auto v2 = engine.process(net(2, 200, kPs, "203.0.113.51", 9001));
  ASSERT_EQ(v1.size(), 1U);
  ASSERT_GE(v2.size(), 1U);
  EXPECT_EQ(v1[0].id, v2.back().id);
  EXPECT_EQ(v1[0].version, 1);
  EXPECT_GT(v2.back().version, 1);
  EXPECT_EQ(v1[0].id, incident_id("WS-T|200|" + std::to_string(t0())));
  EXPECT_EQ(engine.incidents().size(), 1U);
}

TEST(Scorer, OneRuleRepeatingIsNeverAnIncident) {
  // A browser reaching two first-seen destinations: 35 + 17 = 52 >= threshold, but it is one
  // signal type, so it stays a scored tree without an incident.
  Engine engine = test::shipped_engine(false);
  const char* br = "C:\\Apps\\browser.exe";
  engine.process(net(0, 300, br, "198.51.100.20", 443));
  EXPECT_TRUE(engine.process(net(1, 300, br, "198.51.100.21", 443)).empty());
  const auto trees = engine.tree_summaries();
  ASSERT_EQ(trees.size(), 1U);
  EXPECT_EQ(trees[0].score, 52);
  EXPECT_FALSE(trees[0].incident_id.has_value());
}

TEST(Scorer, ACriticalSignalAloneIsAnIncident) {
  Engine engine = test::shipped_engine(false);
  Event access;
  access.id = "a1";
  access.ts_ms = t0();
  access.host = "WS-T";
  access.type = EventType::ProcessAccess;
  access.pid = 900;
  access.image = "C:\\Users\\u\\Downloads\\tool.exe";
  access.target_image = "C:\\Windows\\system32\\lsass.exe";
  access.granted_access = "0x1010";
  const auto updates = engine.process(access);
  ASSERT_EQ(updates.size(), 1U);
  EXPECT_EQ(updates[0].score, 60);
  EXPECT_EQ(updates[0].signals.at(0).rule_id, "lsass-access");
}

TEST(Scorer, HostsAreIndependent) {
  Engine engine = test::shipped_engine(false);
  engine.process(encoded_ps(0, 200, 100));
  engine.process(net(1, 200, kPs, "203.0.113.50", 443, "OTHER-HOST"));
  EXPECT_TRUE(engine.incidents().empty());
}

TEST(Scorer, IncidentJsonHasTheDocumentedShape) {
  Engine engine = test::shipped_engine(false);
  engine.process(encoded_ps(0, 200, 100));
  const auto inc = engine.process(net(1, 200, kPs, "203.0.113.50", 443));
  ASSERT_EQ(inc.size(), 1U);
  const json::Value v = incident_to_json(inc[0]);
  for (const char* key :
       {"kind", "id", "version", "host", "score", "label", "first_seen", "last_seen", "root",
        "signals", "correlations", "breakdown", "attack", "process_tree", "evidence"}) {
    EXPECT_NE(v.find(key), nullptr) << key;
  }
  EXPECT_EQ(v.find("correlations")->as_array()[0].find("multiplier_percent")->as_int(), 150);
  EXPECT_EQ(v.find("first_seen")->as_string(), "2026-10-20T10:00:00.000Z");
}

}  // namespace
}  // namespace edr
