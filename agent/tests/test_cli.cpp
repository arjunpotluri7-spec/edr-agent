#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "cli.hpp"
#include "test_util.hpp"

namespace edr {
namespace {

struct CliRun {
  int code;
  std::string out;
  std::string err;
};

CliRun run_cli(const std::vector<std::string>& args) {
  testing::internal::CaptureStdout();
  testing::internal::CaptureStderr();
  const int code = cli::main_impl(args);
  return {code, testing::internal::GetCapturedStdout(), testing::internal::GetCapturedStderr()};
}

std::string sample(const char* name) {
  return (test::repo() / "samples" / name).string();
}
std::string rules_dir() {
  return (test::repo() / "rules" / "detections").string();
}
std::string scoring() {
  return (test::repo() / "rules" / "scoring.yaml").string();
}

TEST(Cli, VersionAndHelp) {
  const CliRun v = run_cli({"--version"});
  EXPECT_EQ(v.code, 0);
  EXPECT_EQ(v.out, "edr-agent 0.1.0\n");
  EXPECT_EQ(run_cli({"--help"}).code, 0);
  EXPECT_EQ(run_cli({}).code, 2);
  EXPECT_EQ(run_cli({"frobnicate"}).code, 2);
  EXPECT_EQ(run_cli({"replay", "--bogus"}).code, 2);
}

TEST(Cli, RulesCheck) {
  const CliRun r = run_cli({"rules", "check", "--rules-dir", rules_dir(), "--scoring", scoring()});
  EXPECT_EQ(r.code, 0) << r.err;
  EXPECT_NE(r.out.find("rules: 13 loaded"), std::string::npos);
  EXPECT_NE(r.out.find("encoded-ps-then-network"), std::string::npos);
  EXPECT_EQ(run_cli({"rules", "check", "--rules-dir", "/nonexistent"}).code, 2);
}

TEST(Cli, ReplayStdoutJsonl) {
  const CliRun r = run_cli({"replay", sample("scenario_2_phishing_chain.jsonl"), "--stdout",
                            "--format", "jsonl", "--rules-dir", rules_dir(), "--scoring", scoring(),
                            "--baseline", sample("baseline.json")});
  EXPECT_EQ(r.code, 0) << r.err;
  EXPECT_NE(r.out.find("\"kind\":\"incident\""), std::string::npos);
  EXPECT_NE(r.out.find("\"score\":100"), std::string::npos);
  EXPECT_NE(r.out.find("\"kind\":\"tree\""), std::string::npos);
}

TEST(Cli, ReplayTextReportAndFailOnIncident) {
  const CliRun r =
      run_cli({"replay", sample("scenario_4_lolbin_download.jsonl"), "--stdout", "--rules-dir",
               rules_dir(), "--scoring", scoring(), "--fail-on-incident"});
  EXPECT_EQ(r.code, 1);
  EXPECT_NE(r.out.find("INCIDENT inc-"), std::string::npos);
  EXPECT_NE(r.out.find("score 60 (high)"), std::string::npos);
  const CliRun quiet = run_cli({"replay", sample("scenario_5_low_severity_noise.jsonl"), "--stdout",
                                "--rules-dir", rules_dir(), "--scoring", scoring(), "--baseline",
                                sample("baseline.json"), "--fail-on-incident"});
  EXPECT_EQ(quiet.code, 0);
  EXPECT_NE(quiet.out.find("below the incident threshold"), std::string::npos);
}

TEST(Cli, ReplayNeedsAnOutput) {
  EXPECT_EQ(run_cli({"replay", sample("scenario_2_phishing_chain.jsonl")}).code, 2);
  EXPECT_EQ(run_cli({"replay", "/nonexistent.jsonl", "--stdout", "--rules-dir", rules_dir(),
                     "--scoring", scoring()})
                .code,
            3);
}

TEST(Cli, ParseSysmonPrintsJsonLines) {
  const CliRun r =
      run_cli({"parse-sysmon", sample("sysmon_xml/scenario_3_runkey_persistence.xml")});
  EXPECT_EQ(r.code, 0) << r.err;
  EXPECT_NE(r.out.find("\"id\":\"sysmon-WS-CAROL-03-7705\""), std::string::npos);
  const CliRun bad =
      run_cli({"parse-sysmon",
               (test::test_dir() / "fixtures" / "sysmon" / "malformed_doctype.xml").string()});
  EXPECT_EQ(bad.code, 3);
}

#ifndef EDR_WINDOWS_COLLECTORS
TEST(Cli, RunIsWindowsOnly) {
  const CliRun r =
      run_cli({"run", "--config", (test::repo() / "agent" / "agent.example.yaml").string()});
  EXPECT_EQ(r.code, 2);
  EXPECT_NE(r.err.find("only runs on Windows"), std::string::npos);
}
#endif

}  // namespace
}  // namespace edr
