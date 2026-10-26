"""Server-side re-scoring: run the Python engine over a host's stored telemetry.

The agent's incidents are stored as reported; the server independently recomputes them from the
events with the same YAML rules and records both scores. A difference (score_mismatch) means the
agent and server disagree: different rule versions, events the server never received, or a
tampered agent report. Both values stay visible in the API and the dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from edr_server.db import EventRow, IncidentRow, utcnow
from edr_server.engine import Engine, load_baseline, load_rules, load_scoring
from edr_server.engine.config import BaselineKey, RuleSet, Scoring
from edr_server.logsetup import get_logger
from edr_server.settings import Settings

log = get_logger("rescoring")


@dataclass(frozen=True)
class RuleBundle:
    rules: RuleSet
    scoring: Scoring
    baseline: frozenset[BaselineKey]

    @classmethod
    def load(cls, settings: Settings) -> RuleBundle:
        scoring = load_scoring(settings.scoring_file)
        rules = load_rules(settings.rules_dir, scoring)
        baseline = load_baseline(settings.baseline_file) if settings.baseline_file else set()
        return cls(rules, scoring, frozenset(baseline))

    def engine(self) -> Engine:
        return Engine(self.rules, self.scoring, self.baseline)


def apply_display(row: IncidentRow) -> None:
    """Display score/label: the server's when it has computed one, else the agent's."""
    detail = row.server_detail or row.agent_detail or {}
    row.score = row.server_score if row.server_score is not None else (row.agent_score or 0)
    row.label = detail.get("label", "low")
    row.first_seen = detail.get("first_seen", row.first_seen or "")
    row.last_seen = detail.get("last_seen", row.last_seen or "")
    root = detail.get("root") or {}
    row.root_image = str(root.get("image", ""))
    row.root_pid = int(root.get("pid", 0) or 0)
    row.signal_count = len(detail.get("signals", []))
    row.attack = list(detail.get("attack", []))
    row.score_mismatch = (
        row.agent_score is not None
        and row.server_score is not None
        and row.agent_score != row.server_score
    )
    row.updated_at = utcnow()


def rescore_host(session: Session, bundle: RuleBundle, host: str, limit: int) -> dict[str, Any]:
    """Re-run the engine over the host's most recent ``limit`` events (oldest first)."""
    rows = session.scalars(
        select(EventRow)
        .where(EventRow.host == host)
        .order_by(EventRow.ts_ms.desc(), EventRow.seq.desc())
        .limit(limit)
    ).all()
    engine = bundle.engine()
    for row in reversed(rows):
        engine.process(row.data)
    incidents = engine.incidents()
    for inc in incidents:
        existing = session.get(IncidentRow, inc["id"])
        if existing is None:
            existing = IncidentRow(
                id=inc["id"],
                host=host,
                agent_version=0,
                first_seen="",
                last_seen="",
                score=0,
                label="low",
            )
            session.add(existing)
        existing.server_score = inc["score"]
        existing.server_detail = inc
        apply_display(existing)
    log.info(
        "host re-scored", extra={"host": host, "events": len(rows), "incidents": len(incidents)}
    )
    return {"events": len(rows), "incidents": len(incidents), "trees": engine.tree_summaries()}
