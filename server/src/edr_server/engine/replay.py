"""Run the Python engine over JSON-lines event files (used by tests, parity checks and smoke runs).

    python -m edr_server.engine.replay samples/scenario_2_phishing_chain.jsonl

Prints one JSON object per line: every incident (latest version) and then every tree summary,
the same records ``edr-agent replay --stdout --format jsonl`` prints.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from edr_server.engine.config import load_baseline, load_rules, load_scoring
from edr_server.engine.scorer import Engine

REPO = Path(__file__).resolve().parents[4]
MAX_LINE_BYTES = 1024 * 1024


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            if len(line) > MAX_LINE_BYTES:
                raise ValueError(f"{path}:{lineno}: line longer than {MAX_LINE_BYTES} bytes")
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{lineno}: invalid JSON: {exc.msg}") from exc


def build_engine(rules_dir: Path, scoring_file: Path, baseline_file: Path | None) -> Engine:
    scoring = load_scoring(scoring_file)
    return Engine(load_rules(rules_dir, scoring), scoring, load_baseline(baseline_file))


def run(paths: list[Path], engine: Engine) -> list[dict[str, Any]]:
    for path in paths:
        for event in read_jsonl(path):
            engine.process(event)
    return engine.incidents() + engine.tree_summaries()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay events through the Python engine.")
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--rules-dir", type=Path, default=REPO / "rules" / "detections")
    parser.add_argument("--scoring", type=Path, default=REPO / "rules" / "scoring.yaml")
    parser.add_argument("--baseline", type=Path, default=REPO / "samples" / "baseline.json")
    args = parser.parse_args(argv)
    engine = build_engine(args.rules_dir, args.scoring, args.baseline)
    for record in run(args.files, engine):
        sys.stdout.write(json.dumps(record, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
