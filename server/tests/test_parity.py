"""Cross-check: the C++ agent and the Python server must score every sample identically.

Runs ``edr-agent replay --stdout --format jsonl`` if the binary has been built (CI builds it
before this job); otherwise these tests are skipped with the reason below.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from edr_server.engine.replay import run

from .conftest import BASELINE, REPO, RULES, SAMPLES, SCENARIOS, SCORING, engine


def find_agent() -> Path | None:
    env = os.environ.get("EDR_AGENT_BIN")
    if env:
        return Path(env)
    for preset in ("dev", "release", "asan", "windows-msvc"):
        for name in ("edr-agent", "edr-agent.exe"):
            candidate = REPO / "agent" / "build" / preset / name
            if candidate.is_file():
                return candidate
    found = shutil.which("edr-agent")
    return Path(found) if found else None


AGENT = find_agent()
pytestmark = pytest.mark.skipif(
    AGENT is None,
    reason="C++ agent not built: run `cmake --preset dev && cmake --build --preset dev` in "
    "agent/ (or set EDR_AGENT_BIN) to enable the C++/Python parity check",
)


def agent_jsonl(*files: Path) -> list[dict]:
    assert AGENT is not None
    out = subprocess.run(
        [
            str(AGENT),
            "replay",
            *map(str, files),
            "--stdout",
            "--format",
            "jsonl",
            "--rules-dir",
            str(RULES),
            "--scoring",
            str(SCORING),
            "--baseline",
            str(BASELINE),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_cpp_and_python_produce_identical_results(scenario: str) -> None:
    path = SAMPLES / f"{scenario}.jsonl"
    cpp = agent_jsonl(path)
    py = run([path], engine())
    assert cpp == py
    # And the same bytes once serialized compactly (key order included).
    assert [json.dumps(r, separators=(",", ":"), ensure_ascii=False) for r in py] == [
        json.dumps(r, separators=(",", ":"), ensure_ascii=False) for r in cpp
    ]


def test_all_scenarios_in_one_run() -> None:
    files = [SAMPLES / f"{s}.jsonl" for s in SCENARIOS]
    assert agent_jsonl(*files) == run(files, engine())


def test_cpp_yaml_subset_reads_rules_like_pyyaml() -> None:
    assert AGENT is not None
    out = subprocess.run(
        [str(AGENT), "rules", "dump", "--rules-dir", str(RULES), "--scoring", str(SCORING)],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    dumped = json.loads(out.stdout)
    assert dumped["scoring"] == yaml.safe_load(SCORING.read_text())
    expected = {p.name: yaml.safe_load(p.read_text()) for p in sorted(RULES.glob("*.yaml"))}
    assert dumped["rules"] == expected
