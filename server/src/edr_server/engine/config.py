"""Load and validate detection rules, the scoring config and the baseline.

The validation rules (allowed keys, operators, fields, ranges) are the same as in
agent/src/engine/rules.cpp, so ``edr-agent rules check`` and the server reject the same files.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from edr_server.engine.netutil import Network, parse_cidr, parse_ip
from edr_server.engine.textutil import ascii_lower

MAX_RULE_FILE_BYTES = 256 * 1024
MAX_RULES = 500

SEVERITIES = ("low", "medium", "high", "critical")
EVENT_TYPES = frozenset(
    {
        "process_create",
        "process_terminate",
        "image_load",
        "process_access",
        "file_create",
        "file_delete",
        "file_rename",
        "registry_create",
        "registry_set",
        "registry_delete",
        "registry_rename",
        "network_connect",
        "dns_query",
    }
)
FIELDS = frozenset(
    {
        "host",
        "source",
        "type",
        "pid",
        "ppid",
        "image",
        "image_name",
        "command_line",
        "decoded_command",
        "encoded_command_error",
        "user",
        "integrity_level",
        "hashes",
        "process_guid",
        "parent_process_guid",
        "parent_image",
        "parent_image_name",
        "parent_command_line",
        "ancestor_images",
        "target_path",
        "new_path",
        "details",
        "registry_event_type",
        "target_image",
        "granted_access",
        "src_ip",
        "src_port",
        "dest_ip",
        "dest_port",
        "dest_hostname",
        "protocol",
        "initiated",
        "query_name",
        "query_status",
        "query_results",
        "image_loaded",
        "signed",
        "signature",
    }
)
STRING_OPS = ("equals", "contains", "startswith", "endswith")
LEAF_OPS = frozenset(
    {
        *STRING_OPS,
        "regex",
        "gt",
        "gte",
        "lt",
        "lte",
        "exists",
        "cidr",
        "min_label_length",
        "min_label_entropy",
    }
)
_RULE_ID = re.compile(r"[a-z0-9][a-z0-9-]{1,63}")
_ATTACK_ID = re.compile(r"T\d{4}(\.\d{3})?")
_RULE_KEYS = frozenset(
    {"id", "title", "description", "severity", "points", "attack", "event_types", "condition"}
)


class ConfigError(ValueError):
    """A rule, scoring or baseline file is invalid. The message names the file and the problem."""


# ---------------------------------------------------------------------------------------------
# Conditions
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Leaf:
    field: str
    op: str
    values: tuple[Any, ...]
    case_sensitive: bool = False
    compiled: Any = None  # re.Pattern for regex, list[Network] for cidr


@dataclass(frozen=True)
class Node:
    kind: str  # "all", "any", "not", "leaf"
    children: tuple[Node, ...] = ()
    leaf: Leaf | None = None


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else [value]


def _parse_leaf(raw: dict[str, Any], where: str) -> Leaf:
    if "field" not in raw:
        raise ConfigError(f"{where}: condition needs 'field' or one of all/any/not")
    fname = raw["field"]
    if not isinstance(fname, str) or fname not in FIELDS:
        raise ConfigError(f"{where}: unknown field {fname!r}")
    case_sensitive = raw.get("case_sensitive", False)
    if not isinstance(case_sensitive, bool):
        raise ConfigError(f"{where}: case_sensitive must be true or false")
    ops = [k for k in raw if k not in ("field", "case_sensitive")]
    if len(ops) != 1 or ops[0] not in LEAF_OPS:
        raise ConfigError(
            f"{where}: field {fname!r} needs exactly one operator from "
            f"{', '.join(sorted(LEAF_OPS))} (got {', '.join(ops) or 'none'})"
        )
    op = ops[0]
    value = raw[op]
    if op in STRING_OPS:
        items = _as_list(value)
        if not items or not all(isinstance(v, str) and v for v in items):
            raise ConfigError(f"{where}: {op} needs a non-empty string or list of strings")
        if not case_sensitive:
            items = [ascii_lower(v) for v in items]
        return Leaf(fname, op, tuple(items), case_sensitive)
    if op == "regex":
        if not isinstance(value, str) or not value:
            raise ConfigError(f"{where}: regex needs a non-empty string")
        flags = re.ASCII | (0 if case_sensitive else re.IGNORECASE)
        try:
            compiled = re.compile(value, flags)
        except re.error as exc:
            raise ConfigError(f"{where}: invalid regex: {exc}") from exc
        return Leaf(fname, op, (value,), case_sensitive, compiled)
    if op in ("gt", "gte", "lt", "lte", "min_label_length"):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{where}: {op} needs an integer")
        return Leaf(fname, op, (value,), case_sensitive)
    if op == "min_label_entropy":
        if isinstance(value, bool) or not isinstance(value, int | float) or not 0 <= value <= 8:
            raise ConfigError(f"{where}: min_label_entropy needs a number from 0 to 8")
        return Leaf(fname, op, (float(value),), case_sensitive)
    if op == "exists":
        if not isinstance(value, bool):
            raise ConfigError(f"{where}: exists needs true or false")
        return Leaf(fname, op, (value,), case_sensitive)
    # cidr
    items = _as_list(value)
    nets = []
    for item in items:
        net = parse_cidr(item) if isinstance(item, str) else None
        if net is None:
            raise ConfigError(f"{where}: invalid CIDR {item!r}")
        nets.append(net)
    if not nets:
        raise ConfigError(f"{where}: cidr needs at least one network")
    return Leaf(fname, op, tuple(items), case_sensitive, nets)


def parse_condition(raw: Any, where: str, depth: int = 0) -> Node:
    if depth > 16:
        raise ConfigError(f"{where}: condition nested too deeply (max 16)")
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: condition must be a mapping")
    combinators = [k for k in ("all", "any", "not") if k in raw]
    if combinators:
        if len(raw) != 1:
            raise ConfigError(f"{where}: {combinators[0]} must be the only key in its mapping")
        kind = combinators[0]
        if kind == "not":
            return Node("not", (parse_condition(raw["not"], where, depth + 1),))
        items = raw[kind]
        if not isinstance(items, list) or not items:
            raise ConfigError(f"{where}: {kind} needs a non-empty list")
        return Node(kind, tuple(parse_condition(i, where, depth + 1) for i in items))
    return Node("leaf", leaf=_parse_leaf(raw, where))


# ---------------------------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    severity: str
    points: int
    attack: tuple[str, ...]
    event_types: frozenset[str]
    condition: Node
    path: str


@dataclass
class RuleSet:
    rules: list[Rule] = field(default_factory=list)

    def by_id(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)


def _str_list(value: Any, where: str, key: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where}: {key} must be a non-empty list of strings")
    return value


def parse_rule(raw: Any, where: str, severity_points: dict[str, int]) -> Rule:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: a rule file must contain a mapping")
    unknown = sorted(set(raw) - _RULE_KEYS)
    if unknown:
        raise ConfigError(f"{where}: unknown key(s): {', '.join(unknown)}")
    for key in ("id", "title", "severity", "event_types", "condition"):
        if key not in raw:
            raise ConfigError(f"{where}: missing required key '{key}'")
    rid = raw["id"]
    if not isinstance(rid, str) or not _RULE_ID.fullmatch(rid):
        raise ConfigError(f"{where}: id must match [a-z0-9][a-z0-9-]{{1,63}}")
    title = raw["title"]
    if not isinstance(title, str) or not title.strip():
        raise ConfigError(f"{where}: title must be a non-empty string")
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise ConfigError(f"{where}: description must be a string")
    severity = raw["severity"]
    if severity not in SEVERITIES:
        raise ConfigError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
    points = raw.get("points", severity_points[severity])
    if isinstance(points, bool) or not isinstance(points, int) or not 0 <= points <= 100:
        raise ConfigError(f"{where}: points must be an integer from 0 to 100")
    attack = _str_list(raw.get("attack", []), where, "attack") if "attack" in raw else []
    for tid in attack:
        if not _ATTACK_ID.fullmatch(tid):
            raise ConfigError(f"{where}: {tid!r} is not an ATT&CK technique id like T1059.001")
    types = _str_list(raw["event_types"], where, "event_types")
    for t in types:
        if t not in EVENT_TYPES:
            raise ConfigError(f"{where}: unknown event type {t!r}")
    condition = parse_condition(raw["condition"], f"{where} (rule {rid})")
    return Rule(
        rid,
        title.strip(),
        description,
        severity,
        points,
        tuple(attack),
        frozenset(types),
        condition,
        where,
    )


def _read_yaml(path: Path, max_bytes: int) -> Any:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read: {exc.strerror}") from exc
    if size > max_bytes:
        raise ConfigError(f"{path}: file is larger than {max_bytes} bytes")
    try:
        return yaml.safe_load(path.read_text("utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"{path}: cannot parse YAML: {exc}") from exc


def load_rules(rules_dir: Path, scoring: Scoring) -> RuleSet:
    """Load every ``*.yaml`` file in ``rules_dir`` (sorted by file name), one rule per file."""
    if not rules_dir.is_dir():
        raise ConfigError(f"{rules_dir}: not a directory")
    files = sorted(p for p in rules_dir.iterdir() if p.suffix == ".yaml" and p.is_file())
    if not files:
        raise ConfigError(f"{rules_dir}: no .yaml rule files found")
    if len(files) > MAX_RULES:
        raise ConfigError(f"{rules_dir}: more than {MAX_RULES} rule files")
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for path in files:
        rule = parse_rule(_read_yaml(path, MAX_RULE_FILE_BYTES), str(path), scoring.severity_points)
        if rule.id in seen or rule.id == scoring.anomalous.id:
            raise ConfigError(f"{path}: duplicate rule id {rule.id!r}")
        seen[rule.id] = str(path)
        rules.append(rule)
    rules.sort(key=lambda r: r.id)
    known = set(seen) | ({scoring.anomalous.id} if scoring.anomalous.enabled else set())
    for corr in scoring.correlations:
        for req in corr.requires:
            if req not in known:
                raise ConfigError(
                    f"scoring: correlation {corr.id!r} requires unknown signal {req!r}"
                )
    return RuleSet(rules)


# ---------------------------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Correlation:
    id: str
    title: str
    requires: tuple[str, ...]
    ordered: bool
    within_ms: int
    multiplier_percent: int
    bonus: int
    min_score: int


@dataclass(frozen=True)
class AnomalousOutbound:
    enabled: bool
    id: str
    title: str
    severity: str
    points: int
    attack: tuple[str, ...]
    learn: bool
    trusted: tuple[Network, ...]
    untrusted: tuple[Network, ...]
    trusted_text: tuple[str, ...]
    untrusted_text: tuple[str, ...]


@dataclass(frozen=True)
class Scoring:
    window_ms: int
    incident_threshold: int
    incident_min_distinct: int
    labels: tuple[tuple[str, int], ...]  # sorted by minimum, ascending
    severity_points: dict[str, int]
    decay_percent: int
    max_counted: int
    low_severity_cap: int
    boundary_images: frozenset[str]
    max_depth: int
    anomalous: AnomalousOutbound
    correlations: tuple[Correlation, ...]

    def label_for(self, score: int) -> str:
        label = self.labels[0][0]
        for name, minimum in self.labels:
            if score >= minimum:
                label = name
        return label


def _int(raw: dict[str, Any], key: str, where: str, lo: int, hi: int, default: int | None = None):
    if key not in raw:
        if default is None:
            raise ConfigError(f"{where}: missing required key '{key}'")
        return default
    value = raw[key]
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise ConfigError(f"{where}: {key} must be an integer from {lo} to {hi}")
    return value


def _check_keys(raw: Any, allowed: set[str], where: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: must be a mapping")
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ConfigError(f"{where}: unknown key(s): {', '.join(unknown)}")
    return raw


def _cidrs(values: Any, where: str) -> tuple[tuple[Network, ...], tuple[str, ...]]:
    if values is None:
        return (), ()
    if not isinstance(values, list):
        raise ConfigError(f"{where}: must be a list of CIDR strings")
    nets = []
    for v in values:
        net = parse_cidr(v) if isinstance(v, str) else None
        if net is None:
            raise ConfigError(f"{where}: invalid CIDR {v!r}")
        nets.append(net)
    return tuple(nets), tuple(values)


def _multiplier_percent(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int | float) or not 1 <= value <= 10:
        raise ConfigError(f"{where}: multiplier must be a number from 1 to 10")
    pct = round(float(value) * 100)
    if abs(pct - float(value) * 100) > 1e-6:
        raise ConfigError(f"{where}: multiplier may have at most two decimal places")
    return pct


def parse_scoring(raw: Any, where: str) -> Scoring:
    top = _check_keys(
        raw,
        {
            "version",
            "window_minutes",
            "incident_threshold",
            "incident_min_distinct_signals",
            "labels",
            "severity_points",
            "repeats",
            "low_severity_cap",
            "tree",
            "anomalous_outbound",
            "correlations",
        },
        where,
    )
    if top.get("version") != 1:
        raise ConfigError(f"{where}: version must be 1")
    window_ms = _int(top, "window_minutes", where, 1, 1440) * 60_000
    threshold = _int(top, "incident_threshold", where, 1, 100)
    min_distinct = _int(top, "incident_min_distinct_signals", where, 1, 10, 2)

    labels_raw = _check_keys(top.get("labels"), set(SEVERITIES), f"{where}: labels")
    labels = tuple(
        sorted(
            ((k, _int(labels_raw, k, f"{where}: labels", 0, 100)) for k in SEVERITIES),
            key=lambda kv: kv[1],
        )
    )
    if labels[0][1] != 0:
        raise ConfigError(f"{where}: labels need one entry with minimum 0")

    sp_raw = _check_keys(top.get("severity_points"), set(SEVERITIES), f"{where}: severity_points")
    severity_points = {k: _int(sp_raw, k, f"{where}: severity_points", 0, 100) for k in SEVERITIES}

    rep = _check_keys(top.get("repeats", {}), {"decay_percent", "max_counted"}, f"{where}: repeats")
    decay = _int(rep, "decay_percent", f"{where}: repeats", 0, 100, 50)
    max_counted = _int(rep, "max_counted", f"{where}: repeats", 1, 100, 3)
    low_cap = _int(top, "low_severity_cap", where, 0, 100, 20)

    tree = _check_keys(top.get("tree", {}), {"boundary_images", "max_depth"}, f"{where}: tree")
    boundary = tree.get("boundary_images", [])
    if not isinstance(boundary, list) or not all(isinstance(b, str) for b in boundary):
        raise ConfigError(f"{where}: tree.boundary_images must be a list of file names")
    max_depth = _int(tree, "max_depth", f"{where}: tree", 1, 64, 16)

    ao_where = f"{where}: anomalous_outbound"
    ao = _check_keys(
        top.get("anomalous_outbound", {"enabled": False}),
        {
            "enabled",
            "id",
            "title",
            "severity",
            "points",
            "attack",
            "learn",
            "trusted_cidrs",
            "untrusted_cidrs",
        },
        ao_where,
    )
    enabled = ao.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigError(f"{ao_where}: enabled must be true or false")
    ao_id = ao.get("id", "anomalous-outbound")
    if not isinstance(ao_id, str) or not _RULE_ID.fullmatch(ao_id):
        raise ConfigError(f"{ao_where}: id must match [a-z0-9][a-z0-9-]{{1,63}}")
    ao_sev = ao.get("severity", "medium")
    if ao_sev not in SEVERITIES:
        raise ConfigError(f"{ao_where}: severity must be one of {', '.join(SEVERITIES)}")
    ao_title = ao.get("title", "Outbound connection not in the host baseline")
    if not isinstance(ao_title, str) or not ao_title:
        raise ConfigError(f"{ao_where}: title must be a non-empty string")
    ao_attack = ao.get("attack", [])
    if not isinstance(ao_attack, list) or not all(
        isinstance(t, str) and _ATTACK_ID.fullmatch(t) for t in ao_attack
    ):
        raise ConfigError(f"{ao_where}: attack must be a list of technique ids")
    learn = ao.get("learn", True)
    if not isinstance(learn, bool):
        raise ConfigError(f"{ao_where}: learn must be true or false")
    trusted, trusted_text = _cidrs(ao.get("trusted_cidrs"), f"{ao_where}: trusted_cidrs")
    untrusted, untrusted_text = _cidrs(ao.get("untrusted_cidrs"), f"{ao_where}: untrusted_cidrs")
    anomalous = AnomalousOutbound(
        enabled,
        ao_id,
        ao_title,
        ao_sev,
        _int(ao, "points", ao_where, 0, 100, severity_points[ao_sev]),
        tuple(ao_attack),
        learn,
        trusted,
        untrusted,
        trusted_text,
        untrusted_text,
    )

    correlations = []
    seen: set[str] = set()
    corr_raw = top.get("correlations", [])
    if not isinstance(corr_raw, list):
        raise ConfigError(f"{where}: correlations must be a list")
    for i, c in enumerate(corr_raw):
        cw = f"{where}: correlations[{i}]"
        c = _check_keys(
            c,
            {
                "id",
                "title",
                "requires",
                "ordered",
                "within_minutes",
                "multiplier",
                "bonus",
                "min_score",
            },
            cw,
        )
        cid = c.get("id")
        if not isinstance(cid, str) or not _RULE_ID.fullmatch(cid):
            raise ConfigError(f"{cw}: id must match [a-z0-9][a-z0-9-]{{1,63}}")
        if cid in seen:
            raise ConfigError(f"{cw}: duplicate correlation id {cid!r}")
        seen.add(cid)
        title = c.get("title", cid)
        if not isinstance(title, str) or not title:
            raise ConfigError(f"{cw}: title must be a non-empty string")
        requires = c.get("requires")
        if (
            not isinstance(requires, list)
            or len(requires) < 2
            or not all(isinstance(r, str) for r in requires)
            or len(set(requires)) != len(requires)
        ):
            raise ConfigError(f"{cw}: requires needs two or more distinct signal ids")
        ordered = c.get("ordered", False)
        if not isinstance(ordered, bool):
            raise ConfigError(f"{cw}: ordered must be true or false")
        within = _int(c, "within_minutes", cw, 1, 1440, window_ms // 60_000) * 60_000
        mult = _multiplier_percent(c.get("multiplier", 1), cw)
        bonus = _int(c, "bonus", cw, 0, 100, 0)
        min_score = _int(c, "min_score", cw, 0, 100, 0)
        if mult == 100 and bonus == 0 and min_score == 0:
            raise ConfigError(f"{cw}: set at least one of multiplier, bonus or min_score")
        correlations.append(
            Correlation(cid, title, tuple(requires), ordered, within, mult, bonus, min_score)
        )

    return Scoring(
        window_ms,
        threshold,
        min_distinct,
        labels,
        severity_points,
        decay,
        max_counted,
        low_cap,
        frozenset(ascii_lower(b) for b in boundary),
        max_depth,
        anomalous,
        tuple(correlations),
    )


def load_scoring(path: Path) -> Scoring:
    return parse_scoring(_read_yaml(path, MAX_RULE_FILE_BYTES), str(path))


# ---------------------------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------------------------

BaselineKey = tuple[str, str, str]  # (host, image file name lower-case, destination IP)


def parse_baseline(raw: Any, where: str) -> set[BaselineKey]:
    if (
        not isinstance(raw, dict)
        or raw.get("version") != 1
        or not isinstance(raw.get("pairs"), list)
    ):
        raise ConfigError(f'{where}: expected {{"version": 1, "pairs": [...]}}')
    pairs: set[BaselineKey] = set()
    for i, pair in enumerate(raw["pairs"]):
        if not isinstance(pair, dict) or set(pair) != {"host", "image", "dest"}:
            raise ConfigError(f"{where}: pairs[{i}] needs exactly host, image and dest")
        if not all(isinstance(pair[k], str) and pair[k] for k in ("host", "image", "dest")):
            raise ConfigError(f"{where}: pairs[{i}] values must be non-empty strings")
        if parse_ip(pair["dest"]) is None:
            raise ConfigError(f"{where}: pairs[{i}].dest is not an IP address")
        pairs.add((pair["host"], ascii_lower(pair["image"]), ascii_lower(pair["dest"])))
    return pairs


def load_baseline(path: Path | None) -> set[BaselineKey]:
    if path is None:
        return set()
    try:
        raw = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"{path}: cannot read baseline: {exc}") from exc
    return parse_baseline(raw, str(path))
