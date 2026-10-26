// Collector interface and the portable ReplayCollector.
//
// Live collectors (SysmonCollector, EtwCollector; Windows only) run on their own threads and push
// into an EventQueue; the agent's main loop is the only consumer and the only thread that touches
// the engine. ReplayCollector reads recorded JSON-lines files and is how the agent is tested on
// macOS and Linux.
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "edr/event.hpp"
#include "edr/log.hpp"

namespace edr {

using EventCallback = std::function<void(Event)>;

class ICollector {
 public:
  ICollector() = default;
  ICollector(const ICollector&) = delete;
  ICollector& operator=(const ICollector&) = delete;
  ICollector(ICollector&&) = delete;
  ICollector& operator=(ICollector&&) = delete;
  virtual ~ICollector() = default;

  [[nodiscard]] virtual std::string_view name() const = 0;
  // Delivers events until the source ends or stop() is called. Returns false on a fatal error
  // (already logged). Live collectors block in here on their own thread.
  virtual bool run(const EventCallback& on_event) = 0;
  // Asks run() to return soon. Safe to call from another thread or a signal/console handler.
  virtual void stop() = 0;
};

// Thread-safe bounded FIFO. When full, new events are dropped and counted (never blocks a
// collector callback, so a slow consumer cannot stall the OS event delivery thread).
class EventQueue {
 public:
  explicit EventQueue(std::size_t capacity) : capacity_(capacity) {}

  bool push(Event ev);
  std::optional<Event> pop_for(std::chrono::milliseconds timeout);
  void close();
  [[nodiscard]] std::uint64_t dropped() const { return dropped_.load(); }
  [[nodiscard]] std::size_t size() const;

 private:
  std::size_t capacity_;
  mutable std::mutex mutex_;
  std::condition_variable cv_;
  std::deque<Event> items_;
  bool closed_ = false;
  std::atomic<std::uint64_t> dropped_{0};
};

struct ReplayStats {
  std::uint64_t lines = 0;
  std::uint64_t events = 0;
  std::uint64_t invalid = 0;
};

class ReplayCollector final : public ICollector {
 public:
  static constexpr std::size_t kMaxLineBytes = std::size_t{1024} * 1024;
  static constexpr std::chrono::milliseconds kMaxSleep{10000};

  // speed <= 0 replays as fast as possible; speed N replays N times faster than recorded.
  ReplayCollector(std::vector<std::filesystem::path> files, double speed, Logger& log);

  [[nodiscard]] std::string_view name() const override { return "replay"; }
  bool run(const EventCallback& on_event) override;
  void stop() override { stop_.store(true); }
  [[nodiscard]] const ReplayStats& stats() const { return stats_; }

 private:
  std::vector<std::filesystem::path> files_;
  double speed_;
  Logger& log_;
  std::atomic<bool> stop_{false};
  ReplayStats stats_;
};

}  // namespace edr
