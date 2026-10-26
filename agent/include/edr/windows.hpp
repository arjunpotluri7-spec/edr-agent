// Windows-only pieces: live collectors, console stop handling, computer name.
// Nothing here blocks, kills, injects into or modifies other processes: the collectors only
// read events Windows already produces (the Sysmon event log channel and ETW providers).
#pragma once

#ifdef EDR_WINDOWS_COLLECTORS

#include <memory>
#include <string>
#include <vector>

#include "edr/collector.hpp"
#include "edr/log.hpp"

namespace edr::windows {

// Subscribes to Microsoft-Windows-Sysmon/Operational (future events) with EvtSubscribe, renders
// each record to XML with EvtRender and maps it with map_sysmon_event. Needs Sysmon installed
// and an account that may read the channel (Administrators or Event Log Readers).
std::unique_ptr<ICollector> make_sysmon_collector(std::string host, Logger& log);

// Real-time ETW consumer (StartTrace / EnableTraceEx2 / OpenTrace / ProcessTrace) for
// Microsoft-Windows-Kernel-Process, -Kernel-Network and -DNS-Client, decoded with TDH.
// Needs administrator rights (or Performance Log Users) to start a trace session.
std::unique_ptr<ICollector> make_etw_collector(std::string host, std::vector<std::string> providers,
                                               Logger& log);

std::string computer_name();
// Ctrl+C / Ctrl+Break / console close set the stop flag.
void install_stop_handler();
bool stop_requested();

// UTF-16 <-> UTF-8 helpers.
std::string to_utf8(const wchar_t* text, std::size_t length);
std::wstring to_wide(const std::string& text);

}  // namespace edr::windows

#endif  // EDR_WINDOWS_COLLECTORS
