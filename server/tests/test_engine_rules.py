"""Rule loading, validation and the shared per-rule cases (same file as the C++ tests)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from edr_server.engine.config import (
    ConfigError,
    load_rules,
    load_scoring,
    parse_rule,
    parse_scoring,
)
from edr_server.engine.encoded import base64_decode, decode_encoded_command, is_encoded_flag

from .conftest import RULES, SAMPLES, SCORING, engine

CASES = [json.loads(line) for line in (SAMPLES / "rule_cases.jsonl").read_text().splitlines()]


def test_shipped_rules_load() -> None:
    scoring = load_scoring(SCORING)
    rules = load_rules(RULES, scoring)
    assert len(rules.rules) == 13
    assert [r.id for r in rules.rules] == sorted(r.id for r in rules.rules)
    assert len(scoring.correlations) == 4
    assert scoring.label_for(55) == "medium"
    assert scoring.label_for(80) == "critical"


@pytest.mark.parametrize("case", CASES, ids=[f"{c['rule']}:{c['name']}" for c in CASES])
def test_rule_case(case: dict) -> None:
    signals = engine(baseline=False).match(case["event"])
    fired = any(s.rule_id == case["rule"] for s in signals)
    assert fired == case["expect"]


def test_every_rule_has_positive_and_negative_cases() -> None:
    scoring = load_scoring(SCORING)
    ids = {r.id for r in load_rules(RULES, scoring).rules}
    assert {c["rule"] for c in CASES if c["expect"]} == ids
    assert {c["rule"] for c in CASES if not c["expect"]} == ids


def _rule(text: str) -> None:
    parse_rule(yaml.safe_load(text), "t.yaml", load_scoring(SCORING).severity_points)


BASE = "id: x1\ntitle: T\nseverity: low\nevent_types: [dns_query]\n"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (BASE + "condition:\n  field: nope\n  contains: a\n", "unknown field"),
        (BASE + "condition:\n  field: image\n", "exactly one operator"),
        (BASE + "condition:\n  field: image\n  regex: '('\n", "invalid regex"),
        (BASE + "condition:\n  field: dest_ip\n  cidr: [10.0.0.0/40]\n", "invalid CIDR"),
        (BASE + "condition:\n  all: []\n", "non-empty list"),
        (BASE + "extra: 1\ncondition:\n  field: image\n  exists: true\n", "unknown key"),
        (BASE + "attack: [X1]\ncondition:\n  field: image\n  exists: true\n", "ATT&CK"),
        (BASE.replace("low", "bad") + "condition:\n  field: image\n  exists: true\n", "severity"),
    ],
)
def test_rule_validation_errors(text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        _rule(text)


def test_scoring_validation(tmp_path: Path) -> None:
    good = yaml.safe_load(SCORING.read_text())
    parse_scoring(good, "s")
    bad = dict(good, correlations=[{"id": "c1", "requires": ["a", "b"]}])
    with pytest.raises(ConfigError, match="at least one"):
        parse_scoring(bad, "s")
    bad = dict(good, correlations=[{"id": "c1", "requires": ["a"], "bonus": 1}])
    with pytest.raises(ConfigError, match="two or more"):
        parse_scoring(bad, "s")
    bad = dict(good, correlations=[{"id": "c1", "requires": ["a", "b"], "multiplier": 1.255}])
    with pytest.raises(ConfigError, match="two decimal"):
        parse_scoring(bad, "s")
    (tmp_path / "r.yaml").write_text(
        "id: r1\ntitle: R\nseverity: low\nevent_types: [dns_query]\n"
        "condition:\n  field: query_name\n  exists: true\n"
    )
    with pytest.raises(ConfigError, match="unknown signal"):
        load_rules(tmp_path, load_scoring(SCORING))


DEMO = (
    "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGUAZAByAC0AYQBnAGUAbgB0ACAAZABlAG0AbwA6ACAAcwBpAG0A"
    "dQBsAGEAdABlAGQAIABkAG8AdwBuAGwAbwBhAGQAIABjAHIAYQBkAGwAZQAnAA=="
)


def test_encoded_command_decoding() -> None:
    assert decode_encoded_command(f"powershell -EncodedCommand {DEMO}").text == (
        "Write-Output 'edr-agent demo: simulated download cradle'"
    )
    assert decode_encoded_command('pwsh -enc "aABpAA"').text == "hi"
    assert decode_encoded_command("pwsh -e PdgA3g==").text == "\U0001f600"
    for cmd, err in [
        ("powershell -enc", "missing payload"),
        ("powershell -enc not*base64!", "invalid base64"),
        ("powershell -enc aGkh", "invalid utf-16le"),
        ("powershell -enc AAA=", "invalid utf-16le"),
        ("powershell -enc ANg=", "invalid utf-16le"),
        ("powershell -enc QQ=", "invalid base64"),
        ("powershell -enc " + "A" * 65540, "payload too large"),
    ]:
        assert decode_encoded_command(cmd).error == err, cmd
    assert not decode_encoded_command("powershell -NoProfile -File x.ps1").found
    assert all(is_encoded_flag(f) for f in ["-e", "-ec", "-enc", "/EncodedCommand"])
    assert not any(is_encoded_flag(f) for f in ["-ex", "-ExecutionPolicy", "--enc", "enc"])
    assert base64_decode("ab-_") is None
