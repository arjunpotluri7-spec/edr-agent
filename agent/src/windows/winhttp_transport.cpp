// WinHttpTransport: HTTPS POST of batches to the EDR server.
// TLS certificate validation is WinHTTP's default (Windows trust store) and is never disabled.
// The enrollment token is sent as "Authorization: Bearer ..." and is never logged.
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include "edr/output.hpp"
#include "edr/windows.hpp"

namespace edr {
namespace {

class WinHttpTransport final : public ITransport {
 public:
  WinHttpTransport(const std::string& url, std::string agent_id, std::string token, Logger& log)
      : agent_id_(std::move(agent_id)), token_(std::move(token)), log_(log) {
    const std::wstring wurl = windows::to_wide(url);
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = static_cast<DWORD>(-1);
    uc.dwHostNameLength = static_cast<DWORD>(-1);
    uc.dwUrlPathLength = static_cast<DWORD>(-1);
    if (WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc) == FALSE) {
      log_.error("invalid server_url", {{"error", std::to_string(GetLastError())}});
      return;
    }
    secure_ = uc.nScheme == INTERNET_SCHEME_HTTPS;
    const std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    session_ = WinHttpOpen(L"edr-agent/0.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session_ == nullptr) {
      log_.error("WinHttpOpen failed", {{"error", std::to_string(GetLastError())}});
      return;
    }
    WinHttpSetTimeouts(session_, 5000, 5000, 10000, 10000);
    connect_ = WinHttpConnect(session_, host.c_str(), uc.nPort, 0);
    if (connect_ == nullptr) {
      log_.error("WinHttpConnect failed", {{"error", std::to_string(GetLastError())}});
    }
  }
  WinHttpTransport(const WinHttpTransport&) = delete;
  WinHttpTransport& operator=(const WinHttpTransport&) = delete;
  WinHttpTransport(WinHttpTransport&&) = delete;
  WinHttpTransport& operator=(WinHttpTransport&&) = delete;
  ~WinHttpTransport() override {
    if (connect_ != nullptr) {
      WinHttpCloseHandle(connect_);
    }
    if (session_ != nullptr) {
      WinHttpCloseHandle(session_);
    }
    SecureZeroMemory(token_.data(), token_.size());
  }

  bool send(std::string_view endpoint, const std::string& body) override {
    if (connect_ == nullptr) {
      return false;
    }
    for (int attempt = 0; attempt < 3; ++attempt) {
      if (attempt > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500 << attempt));
      }
      const DWORD status = post_once(endpoint, body);
      if (status >= 200 && status < 300) {
        return true;
      }
      if (status != 0 && status != 429 && status < 500) {
        log_.error("server rejected batch", {{"status", std::to_string(status)}});
        return false;  // 4xx: retrying will not help
      }
      log_.warn("batch delivery failed, will retry", {{"status", std::to_string(status)}});
    }
    return false;
  }

 private:
  // Returns the HTTP status, or 0 on a transport error (including TLS validation failure).
  DWORD post_once(std::string_view endpoint, const std::string& body) {
    const std::wstring path = windows::to_wide(std::string(endpoint));
    HINTERNET req =
        WinHttpOpenRequest(connect_, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                           WINHTTP_DEFAULT_ACCEPT_TYPES, secure_ ? WINHTTP_FLAG_SECURE : 0);
    if (req == nullptr) {
      return 0;
    }
    std::wstring headers = L"Content-Type: application/json\r\nX-Agent-Id: " +
                           windows::to_wide(agent_id_) + L"\r\nAuthorization: Bearer " +
                           windows::to_wide(token_) + L"\r\n";
    DWORD status = 0;
    const BOOL sent = WinHttpSendRequest(
        req, headers.c_str(), static_cast<DWORD>(-1L), const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0);
    SecureZeroMemory(headers.data(), headers.size() * sizeof(wchar_t));
    if (sent != FALSE && WinHttpReceiveResponse(req, nullptr) != FALSE) {
      DWORD len = sizeof(status);
      if (WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                              WINHTTP_HEADER_NAME_BY_INDEX, &status, &len,
                              WINHTTP_NO_HEADER_INDEX) == FALSE) {
        status = 0;
      }
    } else {
      log_.warn("HTTPS request failed", {{"error", std::to_string(GetLastError())}});
    }
    WinHttpCloseHandle(req);
    return status;
  }

  std::string agent_id_;
  std::string token_;
  Logger& log_;
  bool secure_ = true;
  HINTERNET session_ = nullptr;
  HINTERNET connect_ = nullptr;
};

}  // namespace

std::unique_ptr<ITransport> make_winhttp_transport(const std::string& server_url,
                                                   const std::string& agent_id, std::string token,
                                                   Logger& log) {
  return std::make_unique<WinHttpTransport>(server_url, agent_id, std::move(token), log);
}

}  // namespace edr

#endif  // _WIN32
