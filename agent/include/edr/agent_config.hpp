// agent.yaml: what to collect, which rules to load and where to send results.
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "edr/log.hpp"
#include "edr/rules.hpp"

namespace edr {

enum class OutputMode { Stdout, Spool, Http };

struct AgentConfig {
  std::string agent_id;
  std::string host_name;  // empty: the computer name
  std::filesystem::path rules_dir;
  std::filesystem::path scoring_file;
  std::optional<std::filesystem::path> baseline_file;
  bool sysmon = true;
  bool etw = false;
  std::vector<std::string> etw_providers{"kernel-process", "kernel-network", "dns-client"};
  std::size_t queue_capacity = 10000;
  OutputMode output = OutputMode::Spool;
  std::filesystem::path spool_path;
  std::string server_url;                     // https://host[:port]
  std::string token_env = "EDR_AGENT_TOKEN";  // name of the env var holding the token
  bool send_events = true;
  std::size_t batch_size = 200;
  int flush_interval_seconds = 5;
  LogLevel log_level = LogLevel::Info;
  LogFormat log_format = LogFormat::Text;
};

// Parses and validates; relative paths are resolved against base_dir (the config's directory).
Loaded<AgentConfig> parse_agent_config(const json::Value& raw,
                                       const std::filesystem::path& base_dir,
                                       const std::string& where);
Loaded<AgentConfig> load_agent_config(const std::filesystem::path& path);

// Accepts https://host[:port] for any host, and http:// only for 127.0.0.1, localhost or [::1].
std::optional<std::string> validate_server_url(const std::string& url);

// Reads the enrollment token from the named environment variable. The value is never logged.
std::optional<std::string> read_token(const std::string& env_name);

}  // namespace edr
