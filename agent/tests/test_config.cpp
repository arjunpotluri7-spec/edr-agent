#include <gtest/gtest.h>

#include <cstdlib>
#include <string>
#include <variant>

#include "edr/agent_config.hpp"
#include "edr/yaml.hpp"
#include "test_util.hpp"

namespace edr {
namespace {

Loaded<AgentConfig> parse(const std::string& text) {
  auto raw = yaml::parse(text);
  if (auto* e = std::get_if<yaml::ParseError>(&raw)) {
    return ConfigError{"yaml: " + e->message};
  }
  return parse_agent_config(std::get<json::Value>(raw), "/etc/edr", "agent.yaml");
}

std::string error_of(const std::string& text) {
  auto c = parse(text);
  return std::holds_alternative<ConfigError>(c) ? std::get<ConfigError>(c).message : "";
}

TEST(AgentConfig, DefaultsAndRelativePaths) {
  auto c = parse("agent_id: ws-alice-01\nrules_dir: ../rules/detections\n");
  ASSERT_TRUE(std::holds_alternative<AgentConfig>(c));
  const AgentConfig& cfg = std::get<AgentConfig>(c);
  EXPECT_EQ(cfg.rules_dir.generic_string(), "/etc/rules/detections");
  EXPECT_EQ(cfg.output, OutputMode::Spool);
  EXPECT_TRUE(cfg.sysmon);
  EXPECT_FALSE(cfg.etw);
  EXPECT_EQ(cfg.token_env, "EDR_AGENT_TOKEN");
  EXPECT_EQ(cfg.batch_size, 200U);
}

TEST(AgentConfig, ShippedExampleIsValid) {
  auto c = load_agent_config(test::repo() / "agent" / "agent.example.yaml");
  ASSERT_TRUE(std::holds_alternative<AgentConfig>(c)) << std::get<ConfigError>(c).message;
  EXPECT_TRUE(std::filesystem::is_directory(std::get<AgentConfig>(c).rules_dir));
}

TEST(AgentConfig, RejectsBadValues) {
  EXPECT_NE(error_of("rules_dir: x\n").find("agent_id"), std::string::npos);
  EXPECT_NE(error_of("agent_id: 'a b'\n").find("agent_id"), std::string::npos);
  EXPECT_NE(error_of("agent_id: a\nsurprise: 1\n").find("unknown key"), std::string::npos);
  EXPECT_NE(error_of("agent_id: a\noutput:\n  mode: carrier-pigeon\n").find("mode"),
            std::string::npos);
  EXPECT_NE(error_of("agent_id: a\noutput:\n  batch_size: 0\n").find("batch_size"),
            std::string::npos);
  EXPECT_NE(error_of("agent_id: a\noutput:\n  token_env: 'abc-123=secret'\n").find("token_env"),
            std::string::npos);
  EXPECT_NE(
      error_of("agent_id: a\ncollectors:\n  etw_providers: [kernel-file]\n").find("etw_providers"),
      std::string::npos);
  EXPECT_NE(error_of("agent_id: a\nlogging:\n  level: loud\n").find("level"), std::string::npos);
#ifndef EDR_WINDOWS_COLLECTORS
  EXPECT_NE(error_of("agent_id: a\noutput:\n  mode: http\n  server_url: https://edr.example.com\n")
                .find("only available in the Windows build"),
            std::string::npos);
#endif
}

TEST(AgentConfig, ServerUrlRules) {
  EXPECT_FALSE(validate_server_url("https://edr.example.com").has_value());
  EXPECT_FALSE(validate_server_url("https://edr.example.com:8443/").has_value());
  EXPECT_FALSE(validate_server_url("http://127.0.0.1:8000").has_value());
  EXPECT_FALSE(validate_server_url("http://localhost:8000").has_value());
  EXPECT_FALSE(validate_server_url("http://[::1]:8000").has_value());
  EXPECT_TRUE(validate_server_url("http://edr.example.com").has_value());
  EXPECT_TRUE(validate_server_url("ftp://edr.example.com").has_value());
  EXPECT_TRUE(validate_server_url("https://user:pw@edr.example.com").has_value());
  EXPECT_TRUE(validate_server_url("https://edr.example.com/api").has_value());
  EXPECT_TRUE(validate_server_url("https://").has_value());
}

TEST(AgentConfig, TokenComesFromTheEnvironmentOnly) {
#ifdef _WIN32
  _putenv_s("EDR_TEST_TOKEN_VAR", "test-token-value");
#else
  setenv("EDR_TEST_TOKEN_VAR", "test-token-value", 1);  // NOLINT(concurrency-mt-unsafe)
#endif
  EXPECT_EQ(read_token("EDR_TEST_TOKEN_VAR"), "test-token-value");
  EXPECT_FALSE(read_token("EDR_TEST_TOKEN_VAR_THAT_IS_NOT_SET").has_value());
}

}  // namespace
}  // namespace edr
