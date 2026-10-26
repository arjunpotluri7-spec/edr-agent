# Multi-signal risk scoring

The agent does not raise an alert for every rule match. Each match becomes a **signal** worth a
number of points; signals are grouped by **process tree** inside a short **context window**;
**correlations** multiply, add to or raise the tree's score when known-bad combinations appear;
and only a tree whose score reaches the **incident threshold** (and that contains at least two
different kinds of signal) becomes an **Incident**.

The C++ agent (`agent/src/engine/scorer.cpp`) and the Python server
(`server/src/edr_server/engine/scorer.py`) implement exactly the same steps with integer
arithmetic; `server/tests/test_parity.py` requires byte-identical results on every sample.
All parameters live in [`rules/scoring.yaml`](../rules/scoring.yaml).

## 1. Process trees

For every host the engine keeps a process table built from `process_create` /
`process_terminate` events (and stub entries for parents it never saw start). A signal belongs
to the tree of its process: walk up the parent chain until the parent is unknown, or is one of
the `tree.boundary_images` (shell and service hosts such as `explorer.exe`, `services.exe`,
`svchost.exe`), or `max_depth` is reached. The topmost process reached is the tree root.

So `OUTLOOK.EXE -> WINWORD.EXE -> powershell.exe` is one tree (root `OUTLOOK.EXE`), while two
programs a user starts from Explorer are two separate trees. The incident id is
`inc-` + FNV-1a-64 of `host|root pid|root start time`, so the agent and server agree on it.

## 2. Signals and points

| Source | Points |
|---|---|
| Rule match | `points:` from the rule, or the severity default: low 10, medium 25, high 40, critical 60 |
| Anomalous outbound (built in) | 35, when a `network_connect` goes to a destination that is in `untrusted_cidrs`, or is not in `trusted_cidrs` and not in the host's baseline of (image file name, destination IP) pairs. With `learn: true` the first sighting is reported and then learned. |

Two adjustments keep noise down:

- **Repeats decay.** The *n*-th repeat of the same rule in the same tree earns
  `previous * decay_percent / 100` (integer division, default 50%), and only the first
  `max_counted` hits (default 3) earn anything: 10, 5, 2, 0, 0, ...
- **Low-severity cap.** All low-severity signals in one tree together add at most
  `low_severity_cap` points (default 20).

## 3. Context window

Signals older than `window_minutes` (default 10) relative to the newest signal in the tree no
longer count, and a tree with no new signal for a whole window is closed. Time is event time
(the timestamps in the telemetry), never the wall clock, so replaying a recording gives the same
result as live collection.

## 4. Correlations

A correlation fires when every signal id in `requires` is present in the tree's window; with
`ordered: true` they must appear in that order (equal timestamps count as in order), and the
first and last may be at most `within_minutes` apart. For each fired correlation, in file order:

```
score = (score * multiplier_percent + 50) // 100     # e.g. 1.5 -> 150 (rounded half up)
score = score + bonus
```

After all of them, the score is raised to the highest `min_score` among fired correlations, and
finally capped at 100.

Built-in correlations:

| id | requires | effect |
|---|---|---|
| `office-macro-chain` | office-spawns-script-host, then encoded-powershell | x1.25 |
| `encoded-ps-then-network` | encoded-powershell, then anomalous-outbound | x1.5, at least 60 |
| `temp-binary-persistence` | exec-from-user-temp, then run-key-persistence | +15 |
| `lolbin-download-then-persist` | lolbin-network and startup-folder-drop | x1.5, at least 60 |

## 5. Incident

A tree becomes an Incident when **both** hold:

1. its score is at least `incident_threshold` (default 50), and
2. it contains at least `incident_min_distinct_signals` (default 2) different signal ids,
   unless one of its signals is critical (a single `lsass-access` is enough on its own).

Rule 2 is the multi-signal requirement: one rule firing again and again (a browser reaching a
few first-seen addresses: 35 + 17 = 52) stays a scored tree, not an incident. Every time a new
signal arrives and the score is at or above the previous incident score, a new incident
**version** is emitted (same id); the server keeps the highest version.

Labels: `low` 0-29, `medium` 30-59, `high` 60-79, `critical` 80-100.

## Worked examples

All numbers below are real engine output (see the README's sample output and the tests).

**A. One signal stays a signal.** PowerShell with a valid `-EncodedCommand` and nothing else:
`+40 encoded-powershell` = **40 (medium)**, below the threshold, so no incident
(`Scorer.SingleHitStaysASignalNotAnIncident`).

**B. The resume example: encoded PowerShell + anomalous outbound from the same tree.**

| Step | Contribution | Running score |
|---|---|---|
| encoded-powershell | +40 | 40 |
| anomalous-outbound (203.0.113.50:443 not in baseline for powershell.exe) | +35 | 75 |
| correlation `encoded-ps-then-network` | x1.5 | (75 x 150 + 50) // 100 = 113 |
| cap | | **100 (critical)** |

Without the correlation the same two signals score 75 (high)
(`Scorer.WithoutCorrelationTheSameSignalsScoreLower`); with it the combination is critical.

**C. Persistence without network (sample scenario 3).** `+10 exec-from-user-temp` (low),
`+30 run-key-persistence` = 40, correlation `temp-binary-persistence` `+15` = **55 (medium)**.

**D. Noise (sample scenario 5).** Four discovery commands in one `cmd.exe` session: 10 + 5 + 2
+ 0 (+ 0) = 17. A Temp-folder updater with a random-looking DNS name: 10 + 10 = 20 (cap). No
tree reaches 50, so there is no incident despite 13 rule matches.

**E. Phishing chain (sample scenario 2).** +40 encoded-powershell, +30 office-spawns-script-host,
+25 script-host-nonstandard-port, +35 anomalous-outbound = 130; x1.25 office-macro-chain = 163;
x1.5 encoded-ps-then-network = 245; capped at **100 (critical)**.
