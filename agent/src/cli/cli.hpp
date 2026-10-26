#pragma once

#include <string>
#include <vector>

#include "edr/agent_config.hpp"
#include "edr/log.hpp"

namespace edr::cli {

// argv without the program name. Returns the process exit code.
int main_impl(const std::vector<std::string>& argv);

#ifdef EDR_WINDOWS_COLLECTORS
int run_live(const AgentConfig& config, Logger& log);
#endif

}  // namespace edr::cli
