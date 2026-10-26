// Windows helpers: UTF-16 conversion, computer name, console stop handling.
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <atomic>
#include <string>

#include "edr/windows.hpp"

namespace edr::windows {
namespace {

std::atomic<bool> g_stop{false};

BOOL WINAPI on_console_event(DWORD type) {
  switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      g_stop.store(true);
      return TRUE;
    default:
      return FALSE;
  }
}

}  // namespace

std::string to_utf8(const wchar_t* text, std::size_t length) {
  if (text == nullptr || length == 0) {
    return {};
  }
  const int len = static_cast<int>(length);
  const int needed = WideCharToMultiByte(CP_UTF8, 0, text, len, nullptr, 0, nullptr, nullptr);
  if (needed <= 0) {
    return {};
  }
  std::string out(static_cast<std::size_t>(needed), '\0');
  WideCharToMultiByte(CP_UTF8, 0, text, len, out.data(), needed, nullptr, nullptr);
  return out;
}

std::wstring to_wide(const std::string& text) {
  if (text.empty()) {
    return {};
  }
  const int len = static_cast<int>(text.size());
  const int needed = MultiByteToWideChar(CP_UTF8, 0, text.data(), len, nullptr, 0);
  if (needed <= 0) {
    return {};
  }
  std::wstring out(static_cast<std::size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.data(), len, out.data(), needed);
  return out;
}

std::string computer_name() {
  wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
  DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
  if (GetComputerNameW(buf, &size) == 0) {
    return "UNKNOWN-HOST";
  }
  return to_utf8(buf, size);
}

void install_stop_handler() {
  SetConsoleCtrlHandler(on_console_event, TRUE);
}

bool stop_requested() {
  return g_stop.load();
}

}  // namespace edr::windows

#endif  // _WIN32
