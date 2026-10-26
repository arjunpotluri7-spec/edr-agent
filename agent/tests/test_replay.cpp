#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <vector>

#include "edr/collector.hpp"
#include "edr/log.hpp"
#include "edr/scorer.hpp"
#include "test_util.hpp"

namespace edr {
namespace {

struct Result {
  std::vector<Incident> incidents;
  std::vector<TreeSummary> trees;
  ReplayStats stats;
};

Result replay(const std::string& scenario) {
  std::ostringstream sink;
  Logger log(sink, LogLevel::Warn, LogFormat::Text);
  Engine engine = test::shipped_engine();
  ReplayCollector collector({test::repo() / "samples" / (scenario + ".jsonl")}, 0, log);
  EXPECT_TRUE(collector.run([&](Event ev) { engine.process(std::move(ev)); }));
  return {engine.incidents(), engine.tree_summaries(), collector.stats()};
}

TEST(Replay, BenignAdminDayHasNoIncidentAndNoSignals) {
  const Result r = replay("scenario_1_benign_admin_day");
  EXPECT_EQ(r.stats.invalid, 0U);
  EXPECT_GT(r.stats.events, 20U);
  EXPECT_TRUE(r.incidents.empty());
  EXPECT_TRUE(r.trees.empty());
}

TEST(Replay, PhishingChainIsACriticalIncident) {
  const Result r = replay("scenario_2_phishing_chain");
  ASSERT_EQ(r.incidents.size(), 1U);
  const Incident& inc = r.incidents[0];
  EXPECT_EQ(inc.host, "WS-ALICE-01");
  EXPECT_EQ(inc.score, 100);
  EXPECT_EQ(inc.label, "critical");
  EXPECT_EQ(basename(inc.root_image), "OUTLOOK.EXE");
  std::vector<std::string> ids;
  for (const auto& s : inc.signals) {
    ids.push_back(s.rule_id);
  }
  EXPECT_EQ(ids, (std::vector<std::string>{"encoded-powershell", "office-spawns-script-host",
                                           "script-host-nonstandard-port", "anomalous-outbound"}));
  ASSERT_EQ(inc.correlations.size(), 2U);
  EXPECT_EQ(inc.correlations[1].id, "encoded-ps-then-network");
  bool decoded = false;
  for (const auto& ev : inc.evidence) {
    decoded =
        decoded || ev.decoded_command == "Write-Output 'edr-agent demo: simulated download cradle'";
  }
  EXPECT_TRUE(decoded);
  EXPECT_EQ(inc.process_tree.size(), 3U);  // OUTLOOK -> WINWORD -> powershell
}

TEST(Replay, RunKeyPersistenceIsAMediumIncident) {
  const Result r = replay("scenario_3_runkey_persistence");
  ASSERT_EQ(r.incidents.size(), 1U);
  EXPECT_EQ(r.incidents[0].score, 55);
  EXPECT_EQ(r.incidents[0].label, "medium");
  EXPECT_EQ(r.incidents[0].correlations.at(0).id, "temp-binary-persistence");
}

TEST(Replay, LolbinDownloadIsAHighIncident) {
  const Result r = replay("scenario_4_lolbin_download");
  ASSERT_EQ(r.incidents.size(), 1U);
  EXPECT_EQ(r.incidents[0].score, 60);
  EXPECT_EQ(r.incidents[0].label, "high");
  EXPECT_EQ(r.incidents[0].signals.at(1).detail,
            "192.0.2.80:80 is in untrusted range 192.0.2.0/24");
}

TEST(Replay, LowSeverityNoiseNeverBecomesAnIncident) {
  const Result r = replay("scenario_5_low_severity_noise");
  EXPECT_TRUE(r.incidents.empty());
  ASSERT_EQ(r.trees.size(), 4U);
  int signals = 0;
  for (const auto& t : r.trees) {
    EXPECT_LE(t.score, 20) << t.root_image;
    EXPECT_EQ(t.label, "low");
    signals += t.signals;
  }
  EXPECT_EQ(signals, 13);
}

TEST(Replay, AllScenariosTogetherGiveTheSameResultsAsSeparately) {
  std::ostringstream sink;
  Logger log(sink, LogLevel::Warn, LogFormat::Text);
  Engine engine = test::shipped_engine();
  std::vector<std::filesystem::path> files;
  for (const char* s :
       {"scenario_1_benign_admin_day", "scenario_2_phishing_chain", "scenario_3_runkey_persistence",
        "scenario_4_lolbin_download", "scenario_5_low_severity_noise"}) {
    files.push_back(test::repo() / "samples" / (std::string(s) + ".jsonl"));
  }
  ReplayCollector collector(files, 0, log);
  ASSERT_TRUE(collector.run([&](Event ev) { engine.process(std::move(ev)); }));
  EXPECT_EQ(engine.incidents().size(), 3U);
}

TEST(Replay, InvalidLinesAreSkippedAndCounted) {
  const auto path = std::filesystem::temp_directory_path() / "edr_replay_invalid.jsonl";
  {
    std::ofstream out(path);
    out << "not json\n\n{\"id\":\"x\"}\n"
        << R"({"id":"ok","ts":"2026-10-20T10:00:00Z","host":"H","type":"dns_query","pid":1,)"
        << R"("query_name":"example.com"})" << "\n"
        << R"({"id":"bad-type","ts":"2026-10-20T10:00:00Z","host":"H","type":"nope","pid":1})"
        << "\n";
  }
  std::ostringstream sink;
  Logger log(sink, LogLevel::Warn, LogFormat::Text);
  ReplayCollector collector({path}, 0, log);
  int seen = 0;
  ASSERT_TRUE(collector.run([&](const Event&) { ++seen; }));
  EXPECT_EQ(seen, 1);
  EXPECT_EQ(collector.stats().invalid, 3U);
  EXPECT_NE(sink.str().find("skipping invalid"), std::string::npos);
  std::filesystem::remove(path);
}

TEST(Replay, MissingFileFails) {
  std::ostringstream sink;
  Logger log(sink, LogLevel::Warn, LogFormat::Text);
  ReplayCollector collector({"/nonexistent/edr.jsonl"}, 0, log);
  EXPECT_FALSE(collector.run([](const Event&) {}));
}

TEST(Replay, SpeedScalingSleepsBetweenEvents) {
  const auto path = std::filesystem::temp_directory_path() / "edr_replay_speed.jsonl";
  {
    std::ofstream out(path);
    out << R"({"id":"a","ts":"2026-10-20T10:00:00.000Z","host":"H","type":"dns_query","pid":1,"query_name":"a"})"
        << "\n"
        << R"({"id":"b","ts":"2026-10-20T10:00:02.000Z","host":"H","type":"dns_query","pid":1,"query_name":"b"})"
        << "\n";
  }
  std::ostringstream sink;
  Logger log(sink, LogLevel::Warn, LogFormat::Text);
  ReplayCollector collector({path}, 10.0, log);  // 2 s recorded -> ~200 ms
  const auto start = std::chrono::steady_clock::now();
  ASSERT_TRUE(collector.run([](const Event&) {}));
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - start)
                      .count();
  EXPECT_GE(ms, 180);
  EXPECT_LT(ms, 2000);
  std::filesystem::remove(path);
}

TEST(Queue, DropsWhenFullAndDrainsAfterClose) {
  EventQueue q(2);
  EXPECT_TRUE(q.push(Event{}));
  EXPECT_TRUE(q.push(Event{}));
  EXPECT_FALSE(q.push(Event{}));
  EXPECT_EQ(q.dropped(), 1U);
  q.close();
  EXPECT_TRUE(q.pop_for(std::chrono::milliseconds(0)).has_value());
  EXPECT_TRUE(q.pop_for(std::chrono::milliseconds(0)).has_value());
  EXPECT_FALSE(q.pop_for(std::chrono::milliseconds(0)).has_value());
  EXPECT_FALSE(q.push(Event{}));
}

}  // namespace
}  // namespace edr
