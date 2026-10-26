#include "edr/output.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace edr {

SpoolTransport::SpoolTransport(std::filesystem::path path, Logger& log)
    : path_(std::move(path)), log_(log) {
  std::error_code ec;
  if (std::filesystem::is_symlink(path_, ec)) {
    log_.error("refusing to write the spool through a symlink", {{"path", path_.string()}});
    return;
  }
  ok_ = true;
}

bool SpoolTransport::send(std::string_view endpoint, const std::string& body) {
  if (!ok_) {
    return false;
  }
  const std::string line = "{\"endpoint\":" + json::quote(endpoint) + ",\"body\":" + body + "}\n";
#ifdef _WIN32
  std::FILE* f = nullptr;
  if (_wfopen_s(&f, path_.c_str(), L"ab") != 0 || f == nullptr) {
    log_.error("cannot open spool file", {{"path", path_.string()}});
    return false;
  }
  const bool ok = std::fwrite(line.data(), 1, line.size(), f) == line.size();
  std::fclose(f);
  return ok;
#else
  // open(2) is variadic; the mode argument is required with O_CREAT.
  const int fd = ::open(path_.c_str(),  // NOLINT(cppcoreguidelines-pro-type-vararg)
                        O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    log_.error("cannot open spool file",
               {{"path", path_.string()}, {"error", std::strerror(errno)}});
    return false;
  }
  std::size_t written = 0;
  while (written < line.size()) {
    const ssize_t n = ::write(fd, line.data() + written, line.size() - written);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      log_.error("write to spool failed", {{"error", std::strerror(errno)}});
      ::close(fd);
      return false;
    }
    written += static_cast<std::size_t>(n);
  }
  return ::close(fd) == 0;
#endif
}

BatchingOutput::BatchingOutput(ITransport& transport, std::string agent_id, std::size_t batch_size,
                               bool send_events, Logger& log)
    : transport_(transport),
      agent_id_(std::move(agent_id)),
      batch_size_(batch_size),
      send_events_(send_events),
      log_(log) {}

void BatchingOutput::add_event(const Event& event) {
  if (!send_events_) {
    return;
  }
  json::Array& pending = events_[event.host];
  pending.push_back(event_to_json(event));
  if (pending.size() >= batch_size_) {
    json::Array batch = std::move(pending);
    pending.clear();
    send_batch(event.host, "/api/v1/events", "events", std::move(batch));
  }
}

void BatchingOutput::add_incident(const Incident& incident) {
  json::Array& pending = incidents_[incident.host];
  pending.push_back(incident_to_json(incident));
  if (pending.size() >= batch_size_) {
    json::Array batch = std::move(pending);
    pending.clear();
    send_batch(incident.host, "/api/v1/incidents", "incidents", std::move(batch));
  }
}

bool BatchingOutput::flush() {
  bool ok = true;
  // Events first, so the server already has the telemetry when it re-scores incidents.
  for (auto& [host, items] : events_) {
    if (!items.empty()) {
      ok = send_batch(host, "/api/v1/events", "events", std::move(items)) && ok;
      items.clear();
    }
  }
  for (auto& [host, items] : incidents_) {
    if (!items.empty()) {
      ok = send_batch(host, "/api/v1/incidents", "incidents", std::move(items)) && ok;
      items.clear();
    }
  }
  return ok;
}

bool BatchingOutput::send_batch(const std::string& host, std::string_view endpoint,
                                std::string_view key, json::Array items) {
  const std::size_t count = items.size();
  json::Object body;
  body.emplace_back("agent_id", agent_id_);
  body.emplace_back("host", host);
  body.emplace_back(std::string(key), json::Value(std::move(items)));
  const bool ok = transport_.send(endpoint, json::dump(json::Value(std::move(body))));
  if (ok) {
    ++sent_;
    log_.debug("batch sent",
               {{"endpoint", std::string(endpoint)}, {"items", std::to_string(count)}});
  } else {
    ++failed_;
    log_.error("batch not delivered",
               {{"endpoint", std::string(endpoint)}, {"items", std::to_string(count)}});
  }
  return ok;
}

}  // namespace edr
