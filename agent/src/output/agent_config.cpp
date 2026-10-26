#include "edr/agent_config.hpp"

#include <cstdlib>
#include <exception>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <variant>

#include "edr/textutil.hpp"

namespace edr {
namespace {

struct Invalid : std::exception {
  explicit Invalid(std::string msg) : message(std::move(msg)) {}
  [[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
  std::string message;
};

[[noreturn]] void fail(const std::string& where, const std::string& msg) {
  throw Invalid(where + ": " + msg);
}

void check_keys(const json::Value& v, const std::set<std::string>& allowed,
                const std::string& where) {
  if (!v.is_object()) {
    fail(where, "must be a mapping");
  }
  for (const auto& [k, _] : v.as_object()) {
    if (allowed.count(k) == 0) {
      fail(where, "unknown key '" + k + "'");
    }
  }
}

std::string get_str(const json::Value& v, const char* key, const std::string& where,
                    const std::string& fallback) {
  const json::Value* x = v.find(key);
  if (x == nullptr || x->is_null()) {
    return fallback;
  }
  if (!x->is_string()) {
    fail(where, std::string(key) + " must be a string");
  }
  return x->as_string();
}

bool get_bool(const json::Value& v, const char* key, const std::string& where, bool fallback) {
  const json::Value* x = v.find(key);
  if (x == nullptr) {
    return fallback;
  }
  if (!x->is_bool()) {
    fail(where, std::string(key) + " must be true or false");
  }
  return x->as_bool();
}

std::int64_t get_int(const json::Value& v, const char* key, const std::string& where,
                     std::int64_t lo, std::int64_t hi, std::int64_t fallback) {
  const json::Value* x = v.find(key);
  if (x == nullptr) {
    return fallback;
  }
  if (!x->is_int() || x->as_int() < lo || x->as_int() > hi) {
    fail(where, std::string(key) + " must be an integer from " + std::to_string(lo) + " to " +
                    std::to_string(hi));
  }
  return x->as_int();
}

std::filesystem::path resolve(const std::filesystem::path& base, const std::string& p) {
  const std::filesystem::path path(p);
  return path.is_absolute() ? path : (base / path).lexically_normal();
}

AgentConfig parse_impl(const json::Value& raw, const std::filesystem::path& base,
                       const std::string& where) {
  check_keys(raw,
             {"agent_id", "host_name", "rules_dir", "scoring_file", "baseline_file", "collectors",
              "output", "logging", "queue_capacity"},
             where);
  AgentConfig c;
  c.agent_id = get_str(raw, "agent_id", where, "");
  if (c.agent_id.empty() || c.agent_id.size() > 64 ||
      c.agent_id.find_first_not_of(
          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") !=
          std::string::npos) {
    fail(where, "agent_id is required: 1-64 characters of letters, digits, '-', '_' or '.'");
  }
  c.host_name = get_str(raw, "host_name", where, "");
  c.rules_dir = resolve(base, get_str(raw, "rules_dir", where, "rules/detections"));
  c.scoring_file = resolve(base, get_str(raw, "scoring_file", where, "rules/scoring.yaml"));
  const std::string baseline = get_str(raw, "baseline_file", where, "");
  if (!baseline.empty()) {
    c.baseline_file = resolve(base, baseline);
  }
  c.queue_capacity =
      static_cast<std::size_t>(get_int(raw, "queue_capacity", where, 100, 1000000, 10000));

  const json::Value empty{json::Object{}};
  const json::Value& col = raw.find("collectors") != nullptr ? *raw.find("collectors") : empty;
  const std::string cw = where + ": collectors";
  check_keys(col, {"sysmon", "etw", "etw_providers"}, cw);
  c.sysmon = get_bool(col, "sysmon", cw, true);
  c.etw = get_bool(col, "etw", cw, false);
  if (const json::Value* p = col.find("etw_providers"); p != nullptr) {
    if (!p->is_array()) {
      fail(cw, "etw_providers must be a list");
    }
    c.etw_providers.clear();
    for (const auto& item : p->as_array()) {
      if (!item.is_string() ||
          (item.as_string() != "kernel-process" && item.as_string() != "kernel-network" &&
           item.as_string() != "dns-client")) {
        fail(cw, "etw_providers entries must be kernel-process, kernel-network or dns-client");
      }
      c.etw_providers.push_back(item.as_string());
    }
  }

  const json::Value& out = raw.find("output") != nullptr ? *raw.find("output") : empty;
  const std::string ow = where + ": output";
  check_keys(out,
             {"mode", "spool_path", "server_url", "token_env", "send_events", "batch_size",
              "flush_interval_seconds"},
             ow);
  const std::string mode = get_str(out, "mode", ow, "spool");
  if (mode == "stdout") {
    c.output = OutputMode::Stdout;
  } else if (mode == "spool") {
    c.output = OutputMode::Spool;
  } else if (mode == "http") {
    c.output = OutputMode::Http;
  } else {
    fail(ow, "mode must be stdout, spool or http");
  }
#ifndef EDR_WINDOWS_COLLECTORS
  if (c.output == OutputMode::Http) {
    fail(ow,
         "mode http uses WinHTTP and is only available in the Windows build; use mode spool with "
         "the "
         "Python forwarder (server/src/edr_server/forwarder.py) on this platform");
  }
#endif
  c.spool_path = resolve(base, get_str(out, "spool_path", ow, "edr-agent-spool.jsonl"));
  c.server_url = get_str(out, "server_url", ow, "");
  if (c.output == OutputMode::Http) {
    if (auto err = validate_server_url(c.server_url)) {
      fail(ow, *err);
    }
  }
  c.token_env = get_str(out, "token_env", ow, "EDR_AGENT_TOKEN");
  if (c.token_env.empty() ||
      c.token_env.find_first_not_of(
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != std::string::npos) {
    fail(ow,
         "token_env must be an environment variable name (the token itself never goes in "
         "the config file)");
  }
  c.send_events = get_bool(out, "send_events", ow, true);
  c.batch_size = static_cast<std::size_t>(get_int(out, "batch_size", ow, 1, 1000, 200));
  c.flush_interval_seconds =
      static_cast<int>(get_int(out, "flush_interval_seconds", ow, 1, 3600, 5));

  const json::Value& lg = raw.find("logging") != nullptr ? *raw.find("logging") : empty;
  const std::string lw = where + ": logging";
  check_keys(lg, {"level", "format"}, lw);
  const auto level = parse_log_level(get_str(lg, "level", lw, "info"));
  if (!level) {
    fail(lw, "level must be error, warn, info or debug");
  }
  c.log_level = *level;
  const auto format = parse_log_format(get_str(lg, "format", lw, "text"));
  if (!format) {
    fail(lw, "format must be text or json");
  }
  c.log_format = *format;
  return c;
}

}  // namespace

std::optional<std::string> validate_server_url(const std::string& url) {
  std::string rest;
  bool https = false;
  if (starts_with(url, "https://")) {
    https = true;
    rest = url.substr(8);
  } else if (starts_with(url, "http://")) {
    rest = url.substr(7);
  } else {
    return std::string("server_url must start with https:// (or http:// for localhost only)");
  }
  const std::string authority = rest.substr(0, rest.find('/'));
  if (authority.empty() || authority.find('@') != std::string::npos) {
    return std::string("server_url needs a host and must not contain credentials");
  }
  if (rest.find('/') != std::string::npos && rest.substr(rest.find('/')) != "/") {
    return std::string("server_url must not have a path; the agent appends /api/v1/...");
  }
  std::string host = authority;
  if (host.front() == '[') {
    host = host.substr(0, host.find(']') + 1);
  } else {
    host = host.substr(0, host.find(':'));
  }
  if (!https && host != "127.0.0.1" && ascii_lower(host) != "localhost" && host != "[::1]") {
    return std::string(
        "plain http:// is only allowed for 127.0.0.1, localhost or [::1]; use "
        "https:// for remote servers");
  }
  return std::nullopt;
}

std::optional<std::string> read_token(const std::string& env_name) {
#ifdef _WIN32
  char* value = nullptr;
  std::size_t len = 0;
  if (_dupenv_s(&value, &len, env_name.c_str()) != 0 || value == nullptr) {
    return std::nullopt;
  }
  std::string token(value);
  std::free(value);
#else
  const char* value = std::getenv(env_name.c_str());  // NOLINT(concurrency-mt-unsafe)
  if (value == nullptr) {
    return std::nullopt;
  }
  std::string token(value);
#endif
  if (token.empty()) {
    return std::nullopt;
  }
  return token;
}

Loaded<AgentConfig> parse_agent_config(const json::Value& raw, const std::filesystem::path& base,
                                       const std::string& where) {
  try {
    return parse_impl(raw, base, where);
  } catch (const Invalid& e) {
    return ConfigError{e.message};
  }
}

Loaded<AgentConfig> load_agent_config(const std::filesystem::path& path) {
  auto raw = read_yaml_file(path);
  if (auto* err = std::get_if<ConfigError>(&raw)) {
    return *err;
  }
  return parse_agent_config(std::get<json::Value>(raw), path.parent_path(), path.string());
}

}  // namespace edr
