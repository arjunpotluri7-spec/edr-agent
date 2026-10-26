#include "cli.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include "edr/agent_config.hpp"
#include "edr/collector.hpp"
#include "edr/json.hpp"
#include "edr/log.hpp"
#include "edr/output.hpp"
#include "edr/rules.hpp"
#include "edr/scorer.hpp"
#include "edr/sysmon.hpp"
#include "edr/textutil.hpp"

#ifdef EDR_WINDOWS_COLLECTORS
#include "edr/windows.hpp"
#endif

#ifndef EDR_AGENT_VERSION
#define EDR_AGENT_VERSION "0.0.0"
#endif

namespace edr::cli {
namespace {

constexpr int kExitOk = 0;
constexpr int kExitIncidents = 1;
constexpr int kExitUsage = 2;
constexpr int kExitInput = 3;
constexpr int kExitOutput = 4;

const char* const kUsage =
    "usage:\n"
    "  edr-agent run --config agent.yaml            live Sysmon/ETW collection (Windows, admin)\n"
    "  edr-agent replay FILE.jsonl... [options]     replay recorded events (any OS)\n"
    "  edr-agent rules check [--rules-dir D] [--scoring F]\n"
    "  edr-agent rules dump  [--rules-dir D] [--scoring F]   parsed YAML as JSON (for tests)\n"
    "  edr-agent parse-sysmon FILE.xml [--host NAME]  convert exported Sysmon XML to JSON lines\n"
    "  edr-agent --version | --help\n"
    "\n"
    "replay options:\n"
    "  --stdout              print results instead of sending them (demo mode)\n"
    "  --format text|jsonl   stdout format (default text)\n"
    "  --speed N             replay N times faster than recorded (default: as fast as possible)\n"
    "  --config agent.yaml   take rules, baseline and output settings from an agent config\n"
    "  --rules-dir D         detection rules directory (default rules/detections)\n"
    "  --scoring F           scoring config (default rules/scoring.yaml)\n"
    "  --baseline F          baseline JSON of known (host, image, destination) pairs\n"
    "  --fail-on-incident    exit 1 if any incident was raised\n"
    "\n"
    "global options: --log-level error|warn|info|debug (default warn), --log-format text|json\n"
    "exit codes: 0 ok, 1 incidents (with --fail-on-incident), 2 usage or config error,\n"
    "            3 input error, 4 output error\n";

struct Args {
  std::vector<std::string> positional;
  std::optional<std::string> config;
  std::optional<std::string> rules_dir;
  std::optional<std::string> scoring;
  std::optional<std::string> baseline;
  std::optional<std::string> host;
  std::string format = "text";
  double speed = 0;
  bool to_stdout = false;
  bool fail_on_incident = false;
};

struct UsageError {
  std::string message;
};

std::variant<Args, UsageError> parse_args(const std::vector<std::string>& argv, Logger& log) {
  static const std::vector<std::string> kWithValue{"--config",   "--rules-dir", "--scoring",
                                                   "--baseline", "--host",      "--format",
                                                   "--speed",    "--log-level", "--log-format"};
  Args a;
  for (std::size_t i = 0; i < argv.size(); ++i) {
    const std::string& arg = argv[i];
    std::string value;
    if (std::find(kWithValue.begin(), kWithValue.end(), arg) != kWithValue.end()) {
      if (i + 1 >= argv.size()) {
        return UsageError{arg + " needs a value"};
      }
      value = argv[++i];
    }
    if (arg == "--config") {
      a.config = value;
    } else if (arg == "--rules-dir") {
      a.rules_dir = value;
    } else if (arg == "--scoring") {
      a.scoring = value;
    } else if (arg == "--baseline") {
      a.baseline = value;
    } else if (arg == "--host") {
      a.host = value;
    } else if (arg == "--format") {
      if (value != "text" && value != "jsonl") {
        return UsageError{"--format must be text or jsonl"};
      }
      a.format = value;
    } else if (arg == "--speed") {
      char* end = nullptr;
      const double v = std::strtod(value.c_str(), &end);
      if (value.empty() || end != value.c_str() + value.size() || v < 0 || v > 1e6) {
        return UsageError{"--speed must be a number from 0 to 1000000"};
      }
      a.speed = v;
    } else if (arg == "--stdout") {
      a.to_stdout = true;
    } else if (arg == "--fail-on-incident") {
      a.fail_on_incident = true;
    } else if (arg == "--log-level") {
      const auto level = parse_log_level(value);
      if (!level) {
        return UsageError{"--log-level must be error, warn, info or debug"};
      }
      log.set_level(*level);
    } else if (arg == "--log-format") {
      const auto fmt = parse_log_format(value);
      if (!fmt) {
        return UsageError{"--log-format must be text or json"};
      }
      log.set_format(*fmt);
    } else if (starts_with(arg, "--")) {
      return UsageError{"unknown option " + arg};
    } else {
      a.positional.push_back(arg);
    }
  }
  return a;
}

struct EngineInputs {
  std::filesystem::path rules_dir = "rules/detections";
  std::filesystem::path scoring = "rules/scoring.yaml";
  std::optional<std::filesystem::path> baseline;
};

std::variant<Engine, ConfigError> build_engine(const EngineInputs& in) {
  auto scoring = load_scoring(in.scoring);
  if (auto* e = std::get_if<ConfigError>(&scoring)) {
    return *e;
  }
  auto rules = load_rules(in.rules_dir, std::get<Scoring>(scoring));
  if (auto* e = std::get_if<ConfigError>(&rules)) {
    return *e;
  }
  Baseline baseline;
  if (in.baseline) {
    auto b = load_baseline(*in.baseline);
    if (auto* e = std::get_if<ConfigError>(&b)) {
      return *e;
    }
    baseline = std::get<Baseline>(std::move(b));
  }
  return Engine(std::get<RuleSet>(std::move(rules)), std::get<Scoring>(std::move(scoring)),
                std::move(baseline));
}

std::string pad(std::string s, std::size_t width) {
  if (s.size() < width) {
    s.append(width - s.size(), ' ');
  }
  return s;
}

std::string shorten(std::string_view s, std::size_t max) {
  if (s.size() <= max) {
    return std::string(s);
  }
  std::size_t cut = max - 3;
  while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0U) == 0x80U) {
    --cut;
  }
  return std::string(s.substr(0, cut)) + "...";
}

std::string clock_of(std::int64_t ms) {
  return format_ts(ms).substr(11, 8);
}

std::string format_multiplier(int pct) {
  std::string s = std::to_string(pct / 100);
  const int frac = pct % 100;
  if (frac != 0) {
    s += '.';
    s += static_cast<char>('0' + frac / 10);
    if (frac % 10 != 0) {
      s += static_cast<char>('0' + frac % 10);
    }
  }
  return s;
}

void render_incident(std::ostream& out, const Incident& inc) {
  out << "INCIDENT " << inc.id << "  score " << inc.score << " (" << inc.label << ")  host "
      << inc.host << "  " << clock_of(inc.first_ms) << "-" << clock_of(inc.last_ms) << " UTC\n";
  out << "  root process: " << basename(inc.root_image) << " (pid " << inc.root_pid << ")\n";
  out << "  score breakdown:\n";
  for (const auto& b : inc.breakdown) {
    if (b.kind == "signal") {
      out << "    " << pad("+" + std::to_string(b.points), 6) << pad(b.rule_id, 30) << b.detail
          << "\n";
    } else if (b.kind == "low_cap") {
      out << "    " << pad(std::to_string(b.points), 6) << b.label << "\n";
    } else if (b.kind == "multiplier") {
      out << "    " << pad("x" + format_multiplier(b.multiplier_percent), 6)
          << pad(b.correlation, 30) << b.before << " -> " << b.after << "\n";
    } else if (b.kind == "bonus") {
      out << "    " << pad("+" + std::to_string(b.points), 6) << pad(b.correlation, 30)
          << "correlation bonus -> " << b.after << "\n";
    } else if (b.kind == "floor") {
      out << "    " << pad("min", 6) << pad(b.correlation, 30) << "raised to " << b.after << "\n";
    } else {
      out << "    " << pad("cap", 6) << b.label << "\n";
    }
  }
  std::string attack;
  for (const auto& a : inc.attack) {
    attack += (attack.empty() ? "" : ", ") + a;
  }
  out << "  ATT&CK: " << attack << "\n";
  out << "  process tree:\n";
  for (const auto& n : inc.process_tree) {
    out << "    " << std::string(static_cast<std::size_t>(n.depth) * 2, ' ') << basename(n.image)
        << " (" << n.pid << ")";
    if (!n.command_line.empty()) {
      out << "  " << shorten(n.command_line, 90);
    }
    out << "\n";
  }
  for (const auto& ev : inc.evidence) {
    if (!ev.decoded_command.empty()) {
      out << "  decoded -EncodedCommand (pid " << ev.pid
          << "): " << shorten(ev.decoded_command, 120) << "\n";
    }
  }
  out << "  evidence: " << inc.evidence.size() << " event(s):";
  for (const auto& ev : inc.evidence) {
    out << " " << ev.id;
  }
  out << "\n\n";
}

std::string render_report(const Engine& engine, const ReplayStats& stats,
                          const std::vector<std::string>& files) {
  std::ostringstream out;
  const auto incidents = engine.incidents();
  const auto trees = engine.tree_summaries();
  out << "edr-agent " << EDR_AGENT_VERSION << " replay: " << stats.events << " events from "
      << files.size() << " file(s)";
  if (stats.invalid != 0) {
    out << ", " << stats.invalid << " invalid line(s) skipped";
  }
  out << "\n";
  out << "signals: " << engine.signals_seen() << "  process trees with signals: " << trees.size()
      << "  incidents: " << incidents.size() << " (threshold "
      << engine.scoring().incident_threshold << ")\n\n";
  for (const auto& inc : incidents) {
    render_incident(out, inc);
  }
  bool header = false;
  for (const auto& t : trees) {
    if (t.incident_id) {
      continue;
    }
    if (!header) {
      out << "below the incident threshold (signals only):\n";
      header = true;
    }
    out << "  " << pad(t.host, 14)
        << pad(std::string(basename(t.root_image)) + " (" + std::to_string(t.root_pid) + ")", 30)
        << "score " << pad(std::to_string(t.score), 4) << pad("(" + t.label + ")", 11) << t.signals
        << " signal(s)\n";
  }
  if (trees.empty()) {
    out << "no signals: nothing matched the loaded rules\n";
  }
  return out.str();
}

int cmd_rules(const Args& args, Logger& log) {
  if (args.positional.size() != 2 ||
      (args.positional[1] != "check" && args.positional[1] != "dump")) {
    std::cerr << "edr-agent: usage: edr-agent rules check|dump [--rules-dir D] [--scoring F]\n";
    return kExitUsage;
  }
  EngineInputs in;
  if (args.rules_dir) {
    in.rules_dir = *args.rules_dir;
  }
  if (args.scoring) {
    in.scoring = *args.scoring;
  }
  if (args.positional[1] == "dump") {
    json::Object rules;
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(in.rules_dir, ec)) {
      if (entry.path().extension() == ".yaml") {
        files.push_back(entry.path());
      }
    }
    std::sort(files.begin(), files.end());
    for (const auto& f : files) {
      auto raw = read_yaml_file(f);
      if (auto* e = std::get_if<ConfigError>(&raw)) {
        std::cerr << "edr-agent: " << e->message << "\n";
        return kExitUsage;
      }
      rules.emplace_back(f.filename().string(), std::get<json::Value>(std::move(raw)));
    }
    auto scoring = read_yaml_file(in.scoring);
    if (auto* e = std::get_if<ConfigError>(&scoring)) {
      std::cerr << "edr-agent: " << e->message << "\n";
      return kExitUsage;
    }
    json::Object doc;
    doc.emplace_back("scoring", std::get<json::Value>(std::move(scoring)));
    doc.emplace_back("rules", json::Value(std::move(rules)));
    std::cout << json::dump(json::Value(std::move(doc))) << "\n";
    return kExitOk;
  }
  auto engine = build_engine(in);
  if (auto* e = std::get_if<ConfigError>(&engine)) {
    std::cerr << "edr-agent: rules check failed: " << e->message << "\n";
    return kExitUsage;
  }
  const Engine& eng = std::get<Engine>(engine);
  const Scoring& sc = eng.scoring();
  std::cout << "rules: " << eng.rules().rules.size() << " loaded from " << in.rules_dir.string()
            << "\n";
  for (const auto& r : eng.rules().rules) {
    std::string types;
    for (const auto t : r.event_types) {
      types += (types.empty() ? "" : ",") + std::string(to_string(t));
    }
    std::cout << "  " << pad(r.id, 30) << pad(std::string(to_string(r.severity)), 9)
              << pad(std::to_string(r.points) + " pts", 8) << types << "\n";
  }
  std::cout << "built-in: " << sc.anomalous.id << " "
            << (sc.anomalous.enabled ? "enabled" : "disabled") << " (" << sc.anomalous.points
            << " pts)\n";
  std::cout << "correlations: " << sc.correlations.size() << "\n";
  for (const auto& c : sc.correlations) {
    std::string req;
    for (const auto& r : c.requires_signals) {
      req += (req.empty() ? "" : (c.ordered ? " -> " : " + ")) + r;
    }
    std::cout << "  " << pad(c.id, 30) << "x" << format_multiplier(c.multiplier_percent) << " +"
              << c.bonus << " min " << c.min_score << "  " << req << "\n";
  }
  std::cout << "window " << sc.window_ms / 60000 << " min, incident threshold "
            << sc.incident_threshold << "\n";
  log.debug("rules check passed");
  return kExitOk;
}

int cmd_parse_sysmon(const Args& args, Logger& log) {
  if (args.positional.size() != 2) {
    std::cerr << "edr-agent: usage: edr-agent parse-sysmon FILE.xml [--host NAME]\n";
    return kExitUsage;
  }
  auto text = read_file_capped(args.positional[1], xml::kMaxDocumentBytes);
  if (auto* e = std::get_if<ConfigError>(&text)) {
    std::cerr << "edr-agent: " << e->message << "\n";
    return kExitInput;
  }
  SysmonOptions opts;
  if (args.host) {
    opts.host_override = *args.host;
  }
  auto batch = parse_sysmon_xml(std::get<std::string>(text), opts);
  if (auto* e = std::get_if<xml::ParseError>(&batch)) {
    std::cerr << "edr-agent: " << args.positional[1] << ": XML error at byte " << e->offset << ": "
              << e->message << "\n";
    return kExitInput;
  }
  const SysmonBatch& b = std::get<SysmonBatch>(batch);
  for (const auto& ev : b.events) {
    std::cout << json::dump(event_to_json(ev)) << "\n";
  }
  for (const auto& err : b.errors) {
    log.warn("skipped malformed Sysmon record", {{"error", err}});
  }
  log.info("parse-sysmon done", {{"events", std::to_string(b.events.size())},
                                 {"unsupported", std::to_string(b.unsupported)},
                                 {"malformed", std::to_string(b.errors.size())}});
  return b.events.empty() && !b.errors.empty() ? kExitInput : kExitOk;
}

int cmd_replay(const Args& args, Logger& log) {
  if (args.positional.size() < 2) {
    std::cerr << "edr-agent: replay needs at least one events file\n";
    return kExitUsage;
  }
  std::optional<AgentConfig> config;
  EngineInputs in;
  if (args.config) {
    auto c = load_agent_config(*args.config);
    if (auto* e = std::get_if<ConfigError>(&c)) {
      std::cerr << "edr-agent: " << e->message << "\n";
      return kExitUsage;
    }
    config = std::get<AgentConfig>(std::move(c));
    in.rules_dir = config->rules_dir;
    in.scoring = config->scoring_file;
    in.baseline = config->baseline_file;
  }
  if (args.rules_dir) {
    in.rules_dir = *args.rules_dir;
  }
  if (args.scoring) {
    in.scoring = *args.scoring;
  }
  if (args.baseline) {
    in.baseline = std::filesystem::path(*args.baseline);
  }
  const bool to_stdout = args.to_stdout || (config && config->output == OutputMode::Stdout);
  if (!to_stdout && !config) {
    std::cerr << "edr-agent: replay needs --stdout, or --config with an output section\n";
    return kExitUsage;
  }
  auto built = build_engine(in);
  if (auto* e = std::get_if<ConfigError>(&built)) {
    std::cerr << "edr-agent: " << e->message << "\n";
    return kExitUsage;
  }
  Engine& engine = std::get<Engine>(built);

  std::unique_ptr<ITransport> transport;
  std::unique_ptr<BatchingOutput> output;
  if (!to_stdout) {
    if (config->output == OutputMode::Spool) {
      auto spool = std::make_unique<SpoolTransport>(config->spool_path, log);
      if (!spool->ok()) {
        return kExitOutput;
      }
      transport = std::move(spool);
    } else {
#ifdef EDR_WINDOWS_COLLECTORS
      auto token = read_token(config->token_env);
      if (!token) {
        std::cerr << "edr-agent: environment variable " << config->token_env
                  << " (the enrollment token) is not set\n";
        return kExitUsage;
      }
      transport =
          make_winhttp_transport(config->server_url, config->agent_id, std::move(*token), log);
#else
      return kExitUsage;  // rejected by config validation already
#endif
    }
    output = std::make_unique<BatchingOutput>(*transport, config->agent_id, config->batch_size,
                                              config->send_events, log);
  }

  std::vector<std::filesystem::path> files(args.positional.begin() + 1, args.positional.end());
  ReplayCollector collector(files, args.speed, log);
  const bool ok = collector.run([&](Event ev) {
    if (output) {
      output->add_event(ev);
    }
    for (const auto& inc : engine.process(std::move(ev))) {
      if (output) {
        output->add_incident(inc);
      }
    }
  });
  if (!ok) {
    return kExitInput;
  }
  const ReplayStats& stats = collector.stats();
  log.info("replay finished", {{"events", std::to_string(stats.events)},
                               {"invalid", std::to_string(stats.invalid)},
                               {"signals", std::to_string(engine.signals_seen())}});
  const std::vector<std::string> names(args.positional.begin() + 1, args.positional.end());
  if (to_stdout) {
    if (args.format == "jsonl") {
      for (const auto& inc : engine.incidents()) {
        std::cout << json::dump(incident_to_json(inc)) << "\n";
      }
      for (const auto& t : engine.tree_summaries()) {
        std::cout << json::dump(tree_summary_to_json(t)) << "\n";
      }
    } else {
      std::cout << render_report(engine, stats, names);
    }
  } else if (!output->flush()) {
    return kExitOutput;
  }
  if (stats.events == 0 && stats.invalid > 0) {
    return kExitInput;
  }
  return args.fail_on_incident && !engine.incidents().empty() ? kExitIncidents : kExitOk;
}

int cmd_run(const Args& args, Logger& log) {
  if (!args.config) {
    std::cerr << "edr-agent: run needs --config agent.yaml\n";
    return kExitUsage;
  }
  auto c = load_agent_config(*args.config);
  if (auto* e = std::get_if<ConfigError>(&c)) {
    std::cerr << "edr-agent: " << e->message << "\n";
    return kExitUsage;
  }
  const AgentConfig& config = std::get<AgentConfig>(c);
#ifdef EDR_WINDOWS_COLLECTORS
  log.set_level(config.log_level);
  log.set_format(config.log_format);
  return run_live(config, log);
#else
  (void)config;
  log.error(
      "live collection uses Sysmon and ETW and only runs on Windows; on this platform use "
      "`edr-agent replay` with recorded events (see samples/)");
  return kExitUsage;
#endif
}

}  // namespace

#ifdef EDR_WINDOWS_COLLECTORS
// Live loop: collectors on their own threads -> queue -> engine -> output (Windows only).
int run_live(const AgentConfig& config, Logger& log) {
  EngineInputs in{config.rules_dir, config.scoring_file, config.baseline_file};
  auto built = build_engine(in);
  if (auto* e = std::get_if<ConfigError>(&built)) {
    log.error("cannot load rules", {{"error", e->message}});
    return kExitUsage;
  }
  Engine& engine = std::get<Engine>(built);
  const std::string host = config.host_name.empty() ? windows::computer_name() : config.host_name;

  std::unique_ptr<ITransport> transport;
  if (config.output == OutputMode::Http) {
    auto token = read_token(config.token_env);
    if (!token) {
      log.error("enrollment token environment variable is not set",
                {{"variable", config.token_env}});
      return kExitUsage;
    }
    transport = make_winhttp_transport(config.server_url, config.agent_id, std::move(*token), log);
  } else if (config.output == OutputMode::Spool) {
    transport = std::make_unique<SpoolTransport>(config.spool_path, log);
  }
  std::unique_ptr<BatchingOutput> output;
  if (transport) {
    output = std::make_unique<BatchingOutput>(*transport, config.agent_id, config.batch_size,
                                              config.send_events, log);
  }

  EventQueue queue(config.queue_capacity);
  std::vector<std::unique_ptr<ICollector>> collectors;
  if (config.sysmon) {
    collectors.push_back(windows::make_sysmon_collector(host, log));
  }
  if (config.etw) {
    collectors.push_back(windows::make_etw_collector(host, config.etw_providers, log));
  }
  if (collectors.empty()) {
    log.error("no collectors enabled in the config");
    return kExitUsage;
  }
  std::vector<std::thread> threads;
  std::atomic<int> running{static_cast<int>(collectors.size())};
  for (auto& col : collectors) {
    threads.emplace_back([&queue, &running, &log, raw = col.get()] {
      if (!raw->run([&queue](Event ev) { queue.push(std::move(ev)); })) {
        log.error("collector stopped with an error", {{"collector", std::string(raw->name())}});
      }
      running.fetch_sub(1);
    });
  }
  windows::install_stop_handler();
  log.info("edr-agent running",
           {{"host", host}, {"collectors", std::to_string(collectors.size())}});

  auto last_flush = std::chrono::steady_clock::now();
  while (!windows::stop_requested() && running.load() > 0) {
    if (auto ev = queue.pop_for(std::chrono::milliseconds(500))) {
      if (output) {
        output->add_event(*ev);
      }
      for (const auto& inc : engine.process(std::move(*ev))) {
        if (output) {
          output->add_incident(inc);
        } else {
          std::cout << json::dump(incident_to_json(inc)) << "\n" << std::flush;
        }
      }
    }
    if (output && std::chrono::steady_clock::now() - last_flush >=
                      std::chrono::seconds(config.flush_interval_seconds)) {
      output->flush();
      last_flush = std::chrono::steady_clock::now();
    }
  }
  log.info("stopping collectors");
  for (auto& col : collectors) {
    col->stop();
  }
  for (auto& t : threads) {
    t.join();
  }
  queue.close();
  while (auto ev = queue.pop_for(std::chrono::milliseconds(0))) {
    for (const auto& inc : engine.process(std::move(*ev))) {
      if (output) {
        output->add_incident(inc);
      }
    }
  }
  const bool flushed = !output || output->flush();
  log.info("edr-agent stopped", {{"events", std::to_string(engine.events_seen())},
                                 {"dropped", std::to_string(queue.dropped())}});
  return flushed ? kExitOk : kExitOutput;
}
#endif

int main_impl(const std::vector<std::string>& argv) {
  Logger log(std::cerr, LogLevel::Warn, LogFormat::Text);
  if (argv.empty() || argv[0] == "--help" || argv[0] == "-h" || argv[0] == "help") {
    std::cout << kUsage;
    return argv.empty() ? kExitUsage : kExitOk;
  }
  if (argv[0] == "--version") {
    std::cout << "edr-agent " << EDR_AGENT_VERSION << "\n";
    return kExitOk;
  }
  auto parsed = parse_args(argv, log);
  if (auto* e = std::get_if<UsageError>(&parsed)) {
    std::cerr << "edr-agent: " << e->message << "\n\n" << kUsage;
    return kExitUsage;
  }
  const Args& args = std::get<Args>(parsed);
  if (args.positional.empty()) {
    std::cerr << kUsage;
    return kExitUsage;
  }
  const std::string& cmd = args.positional[0];
  try {
    if (cmd == "replay") {
      return cmd_replay(args, log);
    }
    if (cmd == "rules") {
      return cmd_rules(args, log);
    }
    if (cmd == "parse-sysmon") {
      return cmd_parse_sysmon(args, log);
    }
    if (cmd == "run") {
      return cmd_run(args, log);
    }
  } catch (const std::exception& e) {
    log.error("unexpected error", {{"error", e.what()}});
    return kExitInput;
  }
  std::cerr << "edr-agent: unknown command '" << cmd << "'\n\n" << kUsage;
  return kExitUsage;
}

}  // namespace edr::cli
