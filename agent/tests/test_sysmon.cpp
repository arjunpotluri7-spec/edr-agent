#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <variant>
#include <vector>

#include "edr/json.hpp"
#include "edr/sysmon.hpp"
#include "test_util.hpp"

namespace edr {
namespace {

SysmonBatch parse_file(const std::filesystem::path& p, const SysmonOptions& opts = {}) {
  auto r = parse_sysmon_xml(test::read_text(p), opts);
  if (auto* e = std::get_if<xml::ParseError>(&r)) {
    ADD_FAILURE() << p << ": " << e->message;
    return {};
  }
  return std::get<SysmonBatch>(r);
}

Event single(const char* fixture) {
  const SysmonBatch b = parse_file(test::test_dir() / "fixtures" / "sysmon" / fixture);
  EXPECT_EQ(b.events.size(), 1U) << fixture;
  EXPECT_TRUE(b.errors.empty()) << fixture;
  return b.events.empty() ? Event{} : b.events.front();
}

// The scenario XML files hold the same events as the JSON-lines replays, rendered the way
// EvtRender returns them. Parsing the XML must give back exactly the replay events.
class SysmonScenario : public ::testing::TestWithParam<std::string> {};

TEST_P(SysmonScenario, XmlMapsToTheSameEventsAsTheReplayFile) {
  const std::string name = GetParam();
  const SysmonBatch batch = parse_file(test::repo() / "samples" / "sysmon_xml" / (name + ".xml"));
  EXPECT_TRUE(batch.errors.empty());
  EXPECT_EQ(batch.unsupported, 0U);
  std::vector<Event> expected;
  for (auto& ev : test::read_events(test::repo() / "samples" / (name + ".jsonl"))) {
    if (ev.source == "sysmon") {
      expected.push_back(ev);
    }
  }
  ASSERT_EQ(batch.events.size(), expected.size());
  for (std::size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(json::dump(event_to_json(batch.events[i])), json::dump(event_to_json(expected[i])))
        << name << " event " << i;
  }
}

INSTANTIATE_TEST_SUITE_P(AllScenarios, SysmonScenario,
                         ::testing::Values("scenario_1_benign_admin_day",
                                           "scenario_2_phishing_chain",
                                           "scenario_3_runkey_persistence",
                                           "scenario_4_lolbin_download",
                                           "scenario_5_low_severity_noise"));

TEST(Sysmon, ProcessCreateFieldsFromThePhishingSample) {
  const SysmonBatch b =
      parse_file(test::repo() / "samples" / "sysmon_xml" / "scenario_2_phishing_chain.xml");
  const Event* ps = nullptr;
  for (const auto& ev : b.events) {
    if (ev.pid == 5208 && ev.type == EventType::ProcessCreate) {
      ps = &ev;
    }
  }
  ASSERT_NE(ps, nullptr);
  EXPECT_EQ(ps->host, "WS-ALICE-01");  // FQDN in <Computer> is shortened
  EXPECT_EQ(ps->id, "sysmon-WS-ALICE-01-1006");
  EXPECT_EQ(ps->ppid, 4120);
  EXPECT_EQ(ps->user, "CORP\\alice");
  EXPECT_EQ(ps->integrity_level, "Medium");
  EXPECT_NE(ps->command_line.find("-EncodedCommand"), std::string::npos);
  EXPECT_NE(ps->parent_image.find("WINWORD.EXE"), std::string::npos);
  EXPECT_EQ(format_ts(ps->ts_ms), "2026-10-20T09:15:10.000Z");
}

TEST(Sysmon, ImageLoad) {
  const Event ev = single("event_7_image_load.xml");
  EXPECT_EQ(ev.type, EventType::ImageLoad);
  EXPECT_EQ(ev.image_loaded, "C:\\Users\\frank\\AppData\\Local\\Temp\\demo.dll");
  EXPECT_EQ(ev.signed_flag, "false");
  EXPECT_TRUE(ev.signature.empty());  // "-" means not available
  EXPECT_EQ(format_ts(ev.ts_ms), "2026-10-21T08:00:01.250Z");
}

TEST(Sysmon, ProcessAccessUsesSourceProcessFields) {
  const Event ev = single("event_10_process_access.xml");
  EXPECT_EQ(ev.type, EventType::ProcessAccess);
  EXPECT_EQ(ev.pid, 4500);
  EXPECT_EQ(ev.image, "C:\\Users\\frank\\Downloads\\tool.exe");
  EXPECT_EQ(ev.target_image, "C:\\Windows\\system32\\lsass.exe");
  EXPECT_EQ(ev.granted_access, "0x1010");
  EXPECT_EQ(ev.user, "CORP\\frank");
}

TEST(Sysmon, RegistryDeleteAndRename) {
  const Event del = single("event_12_registry_delete.xml");
  EXPECT_EQ(del.type, EventType::RegistryDelete);
  EXPECT_EQ(del.registry_event_type, "DeleteKey");
  const Event ren = single("event_14_registry_rename.xml");
  EXPECT_EQ(ren.type, EventType::RegistryRename);
  EXPECT_EQ(ren.new_path, "HKLM\\SOFTWARE\\ExampleCorp\\B");
}

TEST(Sysmon, FileDeleteDecodesEntities) {
  EXPECT_EQ(single("event_23_file_delete.xml").target_path,
            "C:\\Users\\frank\\Documents\\old & unused <draft>.txt");
  const Event detected = single("event_26_file_delete_detected.xml");
  EXPECT_EQ(detected.type, EventType::FileDelete);
  EXPECT_EQ(detected.target_path, "C:\\Users\\frank\\Desktop\\caf\xC3\xA9.txt");
  EXPECT_TRUE(detected.hashes.empty());
}

TEST(Sysmon, UnsupportedAndMalformedRecordsAreCountedNotFatal) {
  const auto dir = test::test_dir() / "fixtures" / "sysmon";
  const SysmonBatch unsupported = parse_file(dir / "event_4_unsupported.xml");
  EXPECT_TRUE(unsupported.events.empty());
  EXPECT_EQ(unsupported.unsupported, 1U);
  const SysmonBatch missing = parse_file(dir / "malformed_missing_pid.xml");
  EXPECT_TRUE(missing.events.empty());
  ASSERT_EQ(missing.errors.size(), 1U);
  EXPECT_NE(missing.errors[0].find("ProcessId"), std::string::npos);
  auto doctype = parse_sysmon_xml(test::read_text(dir / "malformed_doctype.xml"), {});
  EXPECT_TRUE(std::holds_alternative<xml::ParseError>(doctype));
}

TEST(Sysmon, HostOverrideAndNonSysmonProvider) {
  SysmonOptions opts;
  opts.host_override = "OVERRIDE-01";
  const SysmonBatch b =
      parse_file(test::test_dir() / "fixtures" / "sysmon" / "event_7_image_load.xml", opts);
  ASSERT_EQ(b.events.size(), 1U);
  EXPECT_EQ(b.events[0].id, "sysmon-OVERRIDE-01-501");
  auto other = parse_sysmon_xml(
      "<Event><System><Provider Name=\"Other\"/><EventID>1</EventID></System></Event>", {});
  ASSERT_TRUE(std::holds_alternative<SysmonBatch>(other));
  EXPECT_EQ(std::get<SysmonBatch>(other).errors.size(), 1U);
}

}  // namespace
}  // namespace edr
