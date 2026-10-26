// Structured logging to stderr: "edr-agent: level: message key=value" or one JSON object/line.
// Log lines never contain the enrollment token (it is not passed to the logger anywhere).
#pragma once

#include <mutex>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace edr {

enum class LogLevel { Error = 0, Warn = 1, Info = 2, Debug = 3 };
enum class LogFormat { Text, Json };

std::optional<LogLevel> parse_log_level(std::string_view text);
std::optional<LogFormat> parse_log_format(std::string_view text);

using LogFields = std::vector<std::pair<std::string, std::string>>;

class Logger {
 public:
  Logger(std::ostream& out, LogLevel level, LogFormat format);

  void log(LogLevel level, std::string_view message, const LogFields& fields = {});
  void error(std::string_view m, const LogFields& f = {}) { log(LogLevel::Error, m, f); }
  void warn(std::string_view m, const LogFields& f = {}) { log(LogLevel::Warn, m, f); }
  void info(std::string_view m, const LogFields& f = {}) { log(LogLevel::Info, m, f); }
  void debug(std::string_view m, const LogFields& f = {}) { log(LogLevel::Debug, m, f); }

  [[nodiscard]] bool enabled(LogLevel level) const { return level <= level_; }
  void set_level(LogLevel level) { level_ = level; }
  void set_format(LogFormat format) { format_ = format; }

 private:
  std::ostream& out_;
  LogLevel level_;
  LogFormat format_;
  std::mutex mutex_;
};

}  // namespace edr
