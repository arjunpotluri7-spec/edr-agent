// Batching output: events and incident versions are grouped per host and handed to a transport
// as the JSON bodies the server's ingest API accepts.
//
//   POST /api/v1/events     {"agent_id": "...", "host": "...", "events": [...]}
//   POST /api/v1/incidents  {"agent_id": "...", "host": "...", "incidents": [...]}
//
// Transports: SpoolTransport (all platforms; JSON lines that server/.../forwarder.py posts over
// HTTPS) and WinHttpTransport (Windows; posts directly with TLS verification on).
#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "edr/event.hpp"
#include "edr/json.hpp"
#include "edr/log.hpp"
#include "edr/scorer.hpp"

namespace edr {

class ITransport {
 public:
  ITransport() = default;
  ITransport(const ITransport&) = delete;
  ITransport& operator=(const ITransport&) = delete;
  ITransport(ITransport&&) = delete;
  ITransport& operator=(ITransport&&) = delete;
  virtual ~ITransport() = default;
  // endpoint is "/api/v1/events" or "/api/v1/incidents"; body is the JSON document.
  virtual bool send(std::string_view endpoint, const std::string& body) = 0;
};

// Appends {"endpoint": ..., "body": {...}} lines to a file created with owner-only permissions.
// Refuses to follow a symlink at the spool path.
class SpoolTransport final : public ITransport {
 public:
  SpoolTransport(std::filesystem::path path, Logger& log);
  bool send(std::string_view endpoint, const std::string& body) override;
  [[nodiscard]] bool ok() const { return ok_; }

 private:
  std::filesystem::path path_;
  Logger& log_;
  bool ok_ = false;
};

#ifdef EDR_WINDOWS_COLLECTORS
// HTTPS POST via WinHTTP. Certificate validation uses the Windows trust store and cannot be
// disabled; plain http is accepted only for localhost (enforced by validate_server_url).
std::unique_ptr<ITransport> make_winhttp_transport(const std::string& server_url,
                                                   const std::string& agent_id, std::string token,
                                                   Logger& log);
#endif

class BatchingOutput {
 public:
  BatchingOutput(ITransport& transport, std::string agent_id, std::size_t batch_size,
                 bool send_events, Logger& log);

  void add_event(const Event& event);
  void add_incident(const Incident& incident);
  // Sends everything pending. Returns false if any send failed.
  bool flush();
  [[nodiscard]] std::uint64_t failed_batches() const { return failed_; }
  [[nodiscard]] std::uint64_t sent_batches() const { return sent_; }

 private:
  bool send_batch(const std::string& host, std::string_view endpoint, std::string_view key,
                  json::Array items);

  ITransport& transport_;
  std::string agent_id_;
  std::size_t batch_size_;
  bool send_events_;
  Logger& log_;
  std::map<std::string, json::Array> events_;
  std::map<std::string, json::Array> incidents_;
  std::uint64_t failed_ = 0;
  std::uint64_t sent_ = 0;
};

}  // namespace edr
