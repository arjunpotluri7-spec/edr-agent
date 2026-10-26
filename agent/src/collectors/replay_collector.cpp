#include <chrono>
#include <fstream>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include "edr/collector.hpp"
#include "edr/json.hpp"

namespace edr {

bool EventQueue::push(Event ev) {
  {
    const std::lock_guard<std::mutex> lock(mutex_);
    if (closed_) {
      return false;
    }
    if (items_.size() >= capacity_) {
      dropped_.fetch_add(1);
      return false;
    }
    items_.push_back(std::move(ev));
  }
  cv_.notify_one();
  return true;
}

std::optional<Event> EventQueue::pop_for(std::chrono::milliseconds timeout) {
  std::unique_lock<std::mutex> lock(mutex_);
  if (!cv_.wait_for(lock, timeout, [&] { return !items_.empty() || closed_; })) {
    return std::nullopt;
  }
  if (items_.empty()) {
    return std::nullopt;
  }
  Event ev = std::move(items_.front());
  items_.pop_front();
  return ev;
}

void EventQueue::close() {
  {
    const std::lock_guard<std::mutex> lock(mutex_);
    closed_ = true;
  }
  cv_.notify_all();
}

std::size_t EventQueue::size() const {
  const std::lock_guard<std::mutex> lock(mutex_);
  return items_.size();
}

ReplayCollector::ReplayCollector(std::vector<std::filesystem::path> files, double speed,
                                 Logger& log)
    : files_(std::move(files)), speed_(speed), log_(log) {}

bool ReplayCollector::run(const EventCallback& on_event) {
  std::optional<std::int64_t> previous_ts;
  for (const auto& path : files_) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
      log_.error("cannot open replay file", {{"path", path.string()}});
      return false;
    }
    std::string line;
    std::uint64_t lineno = 0;
    while (!stop_.load() && std::getline(in, line)) {
      ++lineno;
      ++stats_.lines;
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      if (line.find_first_not_of(" \t") == std::string::npos) {
        continue;
      }
      const std::string where = path.string() + ":" + std::to_string(lineno);
      if (line.size() > kMaxLineBytes) {
        ++stats_.invalid;
        log_.warn("skipping over-long line", {{"where", where}});
        continue;
      }
      auto parsed = json::parse(line);
      if (auto* err = std::get_if<json::ParseError>(&parsed)) {
        ++stats_.invalid;
        log_.warn("skipping invalid JSON", {{"where", where}, {"error", err->message}});
        continue;
      }
      auto ev = event_from_json(std::get<json::Value>(parsed));
      if (auto* err = std::get_if<EventParseError>(&ev)) {
        ++stats_.invalid;
        log_.warn("skipping invalid event", {{"where", where}, {"error", err->message}});
        continue;
      }
      Event& event = std::get<Event>(ev);
      if (speed_ > 0 && previous_ts && event.ts_ms > *previous_ts) {
        const auto gap = std::chrono::milliseconds(
            static_cast<std::int64_t>(static_cast<double>(event.ts_ms - *previous_ts) / speed_));
        std::this_thread::sleep_for(std::min(gap, kMaxSleep));
      }
      previous_ts = event.ts_ms;
      ++stats_.events;
      on_event(std::move(event));
    }
    if (in.bad()) {
      log_.error("read error in replay file", {{"path", path.string()}});
      return false;
    }
  }
  return true;
}

}  // namespace edr
