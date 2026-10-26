#include <gtest/gtest.h>

#include <filesystem>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "edr/output.hpp"
#include "test_util.hpp"

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace edr {
namespace {

class FakeTransport final : public ITransport {
 public:
  bool send(std::string_view endpoint, const std::string& body) override {
    sent.emplace_back(std::string(endpoint), body);
    return ok;
  }
  std::vector<std::pair<std::string, std::string>> sent;
  bool ok = true;
};

Event dns(const std::string& host, int i) {
  Event e;
  e.id = host + "-" + std::to_string(i);
  e.ts_ms = 1792487710000LL + i;
  e.host = host;
  e.type = EventType::DnsQuery;
  e.pid = 1;
  e.query_name = "example.com";
  return e;
}

TEST(Output, BatchesPerHostAndFlushesTheRest) {
  std::ostringstream logs;
  Logger log(logs, LogLevel::Debug, LogFormat::Text);
  FakeTransport t;
  BatchingOutput out(t, "agent-1", 2, true, log);
  out.add_event(dns("A", 1));
  out.add_event(dns("B", 1));
  EXPECT_TRUE(t.sent.empty());
  out.add_event(dns("A", 2));  // A reaches the batch size
  ASSERT_EQ(t.sent.size(), 1U);
  EXPECT_EQ(t.sent[0].first, "/api/v1/events");
  const json::Value body = test::parse_json(t.sent[0].second);
  EXPECT_EQ(body.find("agent_id")->as_string(), "agent-1");
  EXPECT_EQ(body.find("host")->as_string(), "A");
  EXPECT_EQ(body.find("events")->as_array().size(), 2U);
  EXPECT_TRUE(out.flush());
  ASSERT_EQ(t.sent.size(), 2U);
  EXPECT_EQ(test::parse_json(t.sent[1].second).find("host")->as_string(), "B");
  EXPECT_TRUE(out.flush());  // nothing pending
  EXPECT_EQ(t.sent.size(), 2U);
}

TEST(Output, FailuresAreCountedAndEventsCanBeDisabled) {
  std::ostringstream logs;
  Logger log(logs, LogLevel::Warn, LogFormat::Text);
  FakeTransport t;
  t.ok = false;
  BatchingOutput out(t, "agent-1", 10, false, log);
  out.add_event(dns("A", 1));  // send_events=false: dropped
  Incident inc;
  inc.id = "inc-1";
  inc.host = "A";
  inc.label = "high";
  out.add_incident(inc);
  EXPECT_FALSE(out.flush());
  ASSERT_EQ(t.sent.size(), 1U);
  EXPECT_EQ(t.sent[0].first, "/api/v1/incidents");
  EXPECT_EQ(out.failed_batches(), 1U);
  EXPECT_NE(logs.str().find("batch not delivered"), std::string::npos);
}

TEST(Spool, AppendsLinesWithOwnerOnlyPermissions) {
  const auto dir = std::filesystem::temp_directory_path() / "edr_spool_test";
  std::filesystem::remove_all(dir);
  std::filesystem::create_directories(dir);
  std::ostringstream logs;
  Logger log(logs, LogLevel::Warn, LogFormat::Text);
  SpoolTransport spool(dir / "spool.jsonl", log);
  ASSERT_TRUE(spool.ok());
  EXPECT_TRUE(spool.send("/api/v1/events", "{\"events\":[]}"));
  EXPECT_TRUE(spool.send("/api/v1/incidents", "{\"incidents\":[]}"));
  const std::string text = test::read_text(dir / "spool.jsonl");
  EXPECT_EQ(text,
            "{\"endpoint\":\"/api/v1/events\",\"body\":{\"events\":[]}}\n"
            "{\"endpoint\":\"/api/v1/incidents\",\"body\":{\"incidents\":[]}}\n");
#ifndef _WIN32
  struct stat st{};
  ASSERT_EQ(stat((dir / "spool.jsonl").c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0600);
  std::filesystem::create_symlink(dir / "spool.jsonl", dir / "link.jsonl");
  SpoolTransport via_link(dir / "link.jsonl", log);
  EXPECT_FALSE(via_link.ok());
  EXPECT_FALSE(via_link.send("/api/v1/events", "{}"));
#endif
  std::filesystem::remove_all(dir);
}

TEST(Logger, TextAndJsonFormats) {
  std::ostringstream out;
  Logger log(out, LogLevel::Info, LogFormat::Text);
  log.info("hello world", {{"path", "a b"}, {"n", "1"}});
  log.debug("hidden");
  EXPECT_EQ(out.str(), "edr-agent: info: hello world path=\"a b\" n=1\n");
  std::ostringstream js;
  Logger jlog(js, LogLevel::Info, LogFormat::Json);
  jlog.warn("w", {{"k", "v\"q"}});
  const json::Value v = test::parse_json(js.str());
  EXPECT_EQ(v.find("level")->as_string(), "warn");
  EXPECT_EQ(v.find("k")->as_string(), "v\"q");
  EXPECT_NE(v.find("ts"), nullptr);
}

}  // namespace
}  // namespace edr
