"""Process-tree context, rule evaluation and multi-signal risk scoring.

This is the reference description of the algorithm; agent/src/engine/scorer.cpp implements
the same steps in the same order. docs/scoring.md explains it in prose.

Per event:
  1. advance the host clock (event time, never wall-clock) and close trees idle for a window;
  2. update the host's process table (creates, terminates, stub parents);
  3. enrich the event (image_name, parent_image, ancestor_images, decoded_command);
  4. evaluate every rule (sorted by id), then the built-in anomalous-outbound check;
  5. add each signal to its process tree and re-score the tree; at or above the incident
     threshold, emit a new incident version (only if the score did not go down).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from edr_server.engine.conditions import evaluate
from edr_server.engine.config import EVENT_TYPES, BaselineKey, RuleSet, Scoring
from edr_server.engine.encoded import decode_encoded_command
from edr_server.engine.netutil import ip_in_any, parse_ip
from edr_server.engine.textutil import ascii_lower, fnv1a64, format_ts, image_name, parse_ts

MAX_PROCESSES_PER_HOST = 50_000
MAX_EVIDENCE = 25
MAX_TREE_NODES = 50
MAX_CLOSED_TREES = 1000

# String-valued event fields (same list as agent/src/engine/event.cpp).
STRING_FIELDS = (
    "image",
    "command_line",
    "user",
    "integrity_level",
    "hashes",
    "process_guid",
    "parent_process_guid",
    "parent_image",
    "parent_command_line",
    "target_path",
    "new_path",
    "details",
    "registry_event_type",
    "target_image",
    "granted_access",
    "image_loaded",
    "signed",
    "signature",
    "protocol",
    "src_ip",
    "dest_ip",
    "dest_hostname",
    "query_name",
    "query_status",
    "query_results",
    "decoded_command",
    "encoded_command_error",
    "source",
)


class EventError(ValueError):
    """An event is missing a required field or has a bad value."""


@dataclass
class ProcessNode:
    pid: int
    ppid: int | None
    image: str
    command_line: str
    start_ms: int  # 0 for stubs (processes we never saw start)
    end_ms: int | None = None


@dataclass
class Signal:
    rule_id: str
    title: str
    severity: str
    base_points: int
    attack: tuple[str, ...]
    ts_ms: int
    pid: int
    image: str
    event_id: str
    detail: str
    points: int = 0
    repeat: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "points": self.points,
            "base_points": self.base_points,
            "repeat": self.repeat,
            "ts": format_ts(self.ts_ms),
            "pid": self.pid,
            "image": self.image,
            "event_id": self.event_id,
            "detail": self.detail,
            "attack": list(self.attack),
        }


@dataclass
class Tree:
    key: str
    seq: int
    host: str
    root_pid: int
    root_image: str
    root_start_ms: int
    signals: list[Signal] = field(default_factory=list)
    evidence: dict[str, dict[str, Any]] = field(default_factory=dict)
    last_ms: int = 0
    best_score: int = 0
    version: int = 0
    incident: dict[str, Any] | None = None
    last_score: int = 0
    last_label: str = "low"
    total_signals: int = 0


@dataclass
class HostContext:
    now_ms: int = 0
    processes: dict[int, ProcessNode] = field(default_factory=dict)
    trees: dict[str, Tree] = field(default_factory=dict)


def incident_id(tree_key: str) -> str:
    return "inc-" + fnv1a64(tree_key)


def _detail(ev: dict[str, Any]) -> str:
    t = ev["type"]
    if t == "network_connect":
        return f"{ev.get('dest_ip', '')}:{ev.get('dest_port', '')}"
    if t == "dns_query":
        return str(ev.get("query_name", ""))
    if t == "process_access":
        return str(ev.get("target_image", ""))
    if t.startswith(("file_", "registry_")):
        return str(ev.get("target_path", ""))
    return ev.get("image_name", "")


def _opt_int(ev: dict[str, Any], key: str) -> int | None:
    value = ev.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise EventError(f"{key} must be an integer")
    return value


def validate_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Checks one normalized event and returns a copy with ``_ts_ms`` added."""
    if not isinstance(raw, dict):
        raise EventError("event must be a JSON object")
    for key in ("id", "ts", "host", "type"):
        if not isinstance(raw.get(key), str) or not raw[key]:
            raise EventError(f"missing or empty string field '{key}'")
    ts = parse_ts(raw["ts"])
    if ts is None:
        raise EventError(f"bad timestamp {raw['ts']!r}")
    if raw["type"] not in EVENT_TYPES:
        raise EventError(f"unknown event type {raw['type']!r}")
    if _opt_int(raw, "pid") is None:
        raise EventError("missing integer field 'pid'")
    for key in ("ppid", "src_port", "dest_port", "sysmon_event_id", "record_id"):
        _opt_int(raw, key)
    for key in STRING_FIELDS:
        if raw.get(key) is not None and not isinstance(raw[key], str):
            raise EventError(f"{key} must be a string")
    if raw.get("initiated") is not None and not isinstance(raw["initiated"], bool):
        raise EventError("initiated must be true or false")
    # Enrichment fields are always recomputed, never taken from the input.
    ev = {k: v for k, v in raw.items() if v is not None and k not in _ENRICHED}
    ev["_ts_ms"] = ts
    ev.setdefault("image", "")
    return ev


class Engine:
    def __init__(self, rules: RuleSet, scoring: Scoring, baseline: Iterable[BaselineKey] = ()):
        self.rules = rules.rules
        self.scoring = scoring
        self.baseline: set[BaselineKey] = set(baseline)
        self.hosts: dict[str, HostContext] = {}
        self.closed: list[Tree] = []
        self._seq = 0
        self.events_seen = 0
        self.signals_seen = 0

    # -- public API ---------------------------------------------------------------------------

    def process(self, raw: dict[str, Any]) -> list[dict[str, Any]]:
        """Feed one normalized event; returns new incident versions (possibly empty)."""
        ev = self._validate(raw)
        self.events_seen += 1
        hc = self.hosts.setdefault(ev["host"], HostContext())
        ts = ev["_ts_ms"]
        hc.now_ms = max(hc.now_ms, ts)
        self._expire(hc)
        self._update_processes(hc, ev)
        self._enrich(hc, ev)
        updates = []
        for sig in self._signals(ev):
            self.signals_seen += 1
            update = self._add_signal(hc, ev, sig)
            if update is not None:
                updates.append(update)
        return updates

    def match(self, raw: dict[str, Any]) -> list[Signal]:
        """Process table, enrichment and rule evaluation only (no scoring); for rule tests."""
        ev = self._validate(raw)
        hc = self.hosts.setdefault(ev["host"], HostContext())
        hc.now_ms = max(hc.now_ms, ev["_ts_ms"])
        self._update_processes(hc, ev)
        self._enrich(hc, ev)
        return self._signals(ev)

    def trees(self) -> list[Tree]:
        """Every tree that had at least one signal, open or closed, in creation order."""
        open_trees = [t for hc in self.hosts.values() for t in hc.trees.values()]
        return sorted(self.closed + open_trees, key=lambda t: t.seq)

    def tree_summaries(self) -> list[dict[str, Any]]:
        return [
            {
                "kind": "tree",
                "host": t.host,
                "root_pid": t.root_pid,
                "root_image": t.root_image,
                "score": t.best_score,
                "label": self.scoring.label_for(t.best_score),
                "signals": t.total_signals,
                "incident_id": t.incident["id"] if t.incident else None,
            }
            for t in self.trees()
        ]

    def incidents(self) -> list[dict[str, Any]]:
        """Latest version of every incident, in tree creation order."""
        return [t.incident for t in self.trees() if t.incident is not None]

    # -- steps --------------------------------------------------------------------------------

    @staticmethod
    def _validate(raw: dict[str, Any]) -> dict[str, Any]:
        return validate_event(raw)

    def _expire(self, hc: HostContext) -> None:
        cutoff = hc.now_ms - self.scoring.window_ms
        for key in [k for k, t in hc.trees.items() if t.last_ms < cutoff]:
            self.closed.append(hc.trees.pop(key))
        if len(self.closed) > MAX_CLOSED_TREES:
            del self.closed[: len(self.closed) - MAX_CLOSED_TREES]
        ended = [p for p, n in hc.processes.items() if n.end_ms is not None and n.end_ms < cutoff]
        for pid in ended:
            del hc.processes[pid]

    def _update_processes(self, hc: HostContext, ev: dict[str, Any]) -> None:
        pid = ev["pid"]
        t = ev["type"]
        procs = hc.processes
        if t == "process_create":
            ppid = ev.get("ppid")
            if ppid is not None and ppid not in procs and ev.get("parent_image"):
                procs[ppid] = ProcessNode(
                    ppid, None, ev["parent_image"], str(ev.get("parent_command_line", "")), 0
                )
            procs[pid] = ProcessNode(
                pid, ppid, ev["image"], str(ev.get("command_line", "")), ev["_ts_ms"]
            )
        elif t == "process_terminate":
            if pid in procs:
                procs[pid].end_ms = ev["_ts_ms"]
            else:
                procs[pid] = ProcessNode(pid, None, ev["image"], "", 0, ev["_ts_ms"])
        elif pid not in procs:
            procs[pid] = ProcessNode(pid, None, ev["image"], "", 0)
        if len(procs) > MAX_PROCESSES_PER_HOST:
            # Drop the oldest-started entries; ties broken by pid for determinism.
            for victim in sorted(procs.values(), key=lambda n: (n.start_ms, n.pid))[
                : len(procs) - MAX_PROCESSES_PER_HOST
            ]:
                del procs[victim.pid]

    def _enrich(self, hc: HostContext, ev: dict[str, Any]) -> None:
        procs = hc.processes
        ev["image_name"] = image_name(ev["image"])
        node = procs.get(ev["pid"])
        ppid = ev.get("ppid") if ev.get("ppid") is not None else (node.ppid if node else None)
        if not ev.get("parent_image") and ppid is not None and ppid in procs:
            ev["parent_image"] = procs[ppid].image
        if ev.get("parent_image"):
            ev["parent_image_name"] = image_name(ev["parent_image"])
        ancestors: list[str] = []
        cur = ppid
        while cur is not None and cur in procs and len(ancestors) < self.scoring.max_depth:
            ancestors.append(procs[cur].image)
            cur = procs[cur].ppid
        if ancestors:
            ev["ancestor_images"] = ancestors
        cmd = ev.get("command_line")
        if isinstance(cmd, str) and cmd:
            res = decode_encoded_command(cmd)
            if res.text is not None:
                ev["decoded_command"] = res.text
            elif res.error is not None:
                ev["encoded_command_error"] = res.error

    def _signals(self, ev: dict[str, Any]) -> list[Signal]:
        out = []
        detail = _detail(ev)
        for rule in self.rules:
            if ev["type"] in rule.event_types and evaluate(rule.condition, ev):
                out.append(
                    Signal(
                        rule.id,
                        rule.title,
                        rule.severity,
                        rule.points,
                        rule.attack,
                        ev["_ts_ms"],
                        ev["pid"],
                        ev["image"],
                        ev["id"],
                        detail,
                    )
                )
        ao = self.scoring.anomalous
        if ao.enabled and ev["type"] == "network_connect" and ev.get("initiated") is not False:
            reason = self._anomalous_reason(ev)
            if reason is not None:
                out.append(
                    Signal(
                        ao.id,
                        ao.title,
                        ao.severity,
                        ao.points,
                        ao.attack,
                        ev["_ts_ms"],
                        ev["pid"],
                        ev["image"],
                        ev["id"],
                        reason,
                    )
                )
        return out

    def _anomalous_reason(self, ev: dict[str, Any]) -> str | None:
        ao = self.scoring.anomalous
        dest = str(ev.get("dest_ip", ""))
        ip = parse_ip(dest)
        if ip is None:
            return None
        where = f"{dest}:{ev.get('dest_port', '')}"
        hit = ip_in_any(ip, list(ao.untrusted))
        if hit is not None:
            return f"{where} is in untrusted range {ao.untrusted_text[ao.untrusted.index(hit)]}"
        if ip_in_any(ip, list(ao.trusted)) is not None:
            return None
        key = (ev["host"], ev["image_name"], ascii_lower(dest))
        if key in self.baseline:
            return None
        if ao.learn:
            self.baseline.add(key)
        return f"{where} not in baseline for {ev['image_name']}"

    def _root(self, hc: HostContext, pid: int) -> ProcessNode:
        procs = hc.processes
        node = procs[pid]
        depth = 0
        while depth < self.scoring.max_depth:
            parent = procs.get(node.ppid) if node.ppid is not None else None
            if parent is None or image_name(parent.image) in self.scoring.boundary_images:
                break
            if parent.pid == node.pid:
                break
            node = parent
            depth += 1
        return node

    def _add_signal(self, hc: HostContext, ev: dict[str, Any], sig: Signal) -> dict | None:
        sc = self.scoring
        root = self._root(hc, sig.pid)
        key = f"{ev['host']}|{root.pid}|{root.start_ms}"
        tree = hc.trees.get(key)
        if tree is None:
            self._seq += 1
            tree = Tree(key, self._seq, ev["host"], root.pid, root.image, root.start_ms)
            hc.trees[key] = tree
        cutoff = sig.ts_ms - sc.window_ms
        tree.signals = [s for s in tree.signals if s.ts_ms >= cutoff]
        repeat = sum(1 for s in tree.signals if s.rule_id == sig.rule_id)
        points = sig.base_points
        if repeat >= sc.max_counted:
            points = 0
        else:
            for _ in range(repeat):
                points = points * sc.decay_percent // 100
        sig.points = points
        sig.repeat = repeat
        tree.signals.append(sig)
        tree.total_signals += 1
        tree.last_ms = max(tree.last_ms, sig.ts_ms)
        if ev["id"] not in tree.evidence:
            tree.evidence[ev["id"]] = _evidence(ev)

        score, label, breakdown, fired = self.score(tree.signals)
        tree.last_score, tree.last_label = score, label
        tree.best_score = max(tree.best_score, score)
        if score < sc.incident_threshold or not _enough_signal_types(tree.signals, sc):
            return None
        if tree.incident is not None and score < tree.incident["score"]:
            return None
        tree.version += 1
        tree.incident = self._incident(hc, tree, score, label, breakdown, fired)
        return tree.incident

    # -- scoring ------------------------------------------------------------------------------

    def score(self, signals: list[Signal]) -> tuple[int, str, list[dict[str, Any]], list]:
        sc = self.scoring
        breakdown: list[dict[str, Any]] = []
        low_total = 0
        other = 0
        for s in signals:
            breakdown.append(
                {
                    "kind": "signal",
                    "rule_id": s.rule_id,
                    "label": s.title,
                    "detail": s.detail,
                    "points": s.points,
                }
            )
            if s.severity == "low":
                low_total += s.points
            else:
                other += s.points
        low_counted = min(low_total, sc.low_severity_cap)
        if low_counted < low_total:
            breakdown.append(
                {
                    "kind": "low_cap",
                    "label": f"low-severity signals capped at {sc.low_severity_cap}",
                    "points": low_counted - low_total,
                }
            )
        score = other + low_counted
        fired = [c for c in sc.correlations if _fires(c, signals)]
        for c in fired:
            if c.multiplier_percent != 100:
                before = score
                score = (score * c.multiplier_percent + 50) // 100
                breakdown.append(
                    {
                        "kind": "multiplier",
                        "correlation": c.id,
                        "label": c.title,
                        "multiplier_percent": c.multiplier_percent,
                        "before": before,
                        "after": score,
                    }
                )
            if c.bonus:
                score += c.bonus
                breakdown.append(
                    {
                        "kind": "bonus",
                        "correlation": c.id,
                        "label": c.title,
                        "points": c.bonus,
                        "after": score,
                    }
                )
        floor_corr = None
        for c in fired:
            if c.min_score and (floor_corr is None or c.min_score > floor_corr.min_score):
                floor_corr = c
        if floor_corr is not None and score < floor_corr.min_score:
            score = floor_corr.min_score
            breakdown.append(
                {
                    "kind": "floor",
                    "correlation": floor_corr.id,
                    "label": floor_corr.title,
                    "after": score,
                }
            )
        if score > 100:
            score = 100
            breakdown.append({"kind": "cap", "label": "score capped at 100", "after": 100})
        return score, sc.label_for(score), breakdown, fired

    def _incident(
        self,
        hc: HostContext,
        tree: Tree,
        score: int,
        label: str,
        breakdown: list[dict[str, Any]],
        fired: list,
    ) -> dict[str, Any]:
        signals = tree.signals
        attack = sorted({t for s in signals for t in s.attack})
        evidence_ids: list[str] = []
        for s in signals:
            if s.event_id not in evidence_ids:
                evidence_ids.append(s.event_id)
        evidence = [tree.evidence[i] for i in evidence_ids[:MAX_EVIDENCE]]
        return {
            "kind": "incident",
            "id": incident_id(tree.key),
            "version": tree.version,
            "host": tree.host,
            "score": score,
            "label": label,
            "first_seen": format_ts(min(s.ts_ms for s in signals)),
            "last_seen": format_ts(max(s.ts_ms for s in signals)),
            "root": {
                "pid": tree.root_pid,
                "image": tree.root_image,
                "start": format_ts(tree.root_start_ms) if tree.root_start_ms else None,
            },
            "signals": [s.to_dict() for s in signals],
            "correlations": [
                {
                    "id": c.id,
                    "title": c.title,
                    "multiplier_percent": c.multiplier_percent,
                    "bonus": c.bonus,
                    "min_score": c.min_score,
                }
                for c in fired
            ],
            "breakdown": breakdown,
            "attack": attack,
            "process_tree": self._tree_excerpt(hc, tree),
            "evidence": evidence,
        }

    def _tree_excerpt(self, hc: HostContext, tree: Tree) -> list[dict[str, Any]]:
        procs = hc.processes
        chosen: dict[int, int] = {}  # pid -> depth below root
        for s in tree.signals:
            chain: list[int] = []
            cur: int | None = s.pid
            while cur is not None and cur in procs and len(chain) <= self.scoring.max_depth:
                chain.append(cur)
                if cur == tree.root_pid:
                    break
                cur = procs[cur].ppid
            if chain and chain[-1] == tree.root_pid:
                for depth, pid in enumerate(reversed(chain)):
                    chosen.setdefault(pid, depth)
            elif s.pid in procs:
                # The chain to the root was pruned or broken; show the process on its own.
                chosen.setdefault(s.pid, 1)
        nodes = []
        for pid, depth in chosen.items():
            n = procs[pid]
            nodes.append(
                {
                    "pid": n.pid,
                    "ppid": n.ppid,
                    "image": n.image,
                    "command_line": n.command_line,
                    "start": format_ts(n.start_ms) if n.start_ms else None,
                    "depth": depth,
                }
            )
        nodes.sort(key=lambda n: (n["depth"], n["start"] or "", n["pid"]))
        return nodes[:MAX_TREE_NODES]


def _enough_signal_types(signals: list[Signal], sc: Scoring) -> bool:
    """Multi-signal requirement: N distinct rule ids, unless a critical signal is present."""
    if any(s.severity == "critical" for s in signals):
        return True
    return len({s.rule_id for s in signals}) >= sc.incident_min_distinct


def _fires(c, signals: list[Signal]) -> bool:
    times: list[int] = []
    last = None
    for req in c.requires:
        cands = [
            s.ts_ms
            for s in signals
            if s.rule_id == req and (not c.ordered or last is None or s.ts_ms >= last)
        ]
        if not cands:
            return False
        last = min(cands)
        times.append(last)
    return max(times) - min(times) <= c.within_ms


_ENRICHED = {
    "image_name",
    "parent_image_name",
    "ancestor_images",
    "decoded_command",
    "encoded_command_error",
    "_ts_ms",
}
_INT_FIELDS = ("sysmon_event_id", "record_id", "pid", "ppid")


def _evidence(ev: dict[str, Any]) -> dict[str, Any]:
    """Same fields, order and omissions as event_to_json() in agent/src/engine/event.cpp."""
    out: dict[str, Any] = {"id": ev["id"], "ts": format_ts(ev["_ts_ms"]), "host": ev["host"]}
    if ev.get("source"):
        out["source"] = ev["source"]
    out["type"] = ev["type"]
    for key in _INT_FIELDS:
        if ev.get(key) is not None:
            out[key] = ev[key]
    for key in STRING_FIELDS:
        if key != "source" and ev.get(key):
            out[key] = ev[key]
    for key in ("initiated", "src_port", "dest_port"):
        if ev.get(key) is not None:
            out[key] = ev[key]
    return out
