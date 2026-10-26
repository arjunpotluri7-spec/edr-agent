from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from edr_server.app import create_app
from edr_server.engine.replay import build_engine, read_jsonl
from edr_server.security import token_hash
from edr_server.settings import Settings

REPO = Path(__file__).resolve().parents[2]
SAMPLES = REPO / "samples"
RULES = REPO / "rules" / "detections"
SCORING = REPO / "rules" / "scoring.yaml"
BASELINE = SAMPLES / "baseline.json"
SCENARIOS = sorted(p.stem for p in SAMPLES.glob("scenario_*.jsonl"))

# Generated per test session; these are throwaway test credentials, not secrets.
AGENT_ID = "test-agent"
AGENT_TOKEN = secrets.token_urlsafe(32)
OTHER_AGENT = "other-agent"
OTHER_TOKEN = secrets.token_urlsafe(32)


def engine(baseline: bool = True):
    return build_engine(RULES, SCORING, BASELINE if baseline else None)


def scenario_events(name: str) -> list[dict]:
    return list(read_jsonl(SAMPLES / f"{name}.jsonl"))


def agent_headers(agent_id: str = AGENT_ID, token: str = AGENT_TOKEN) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-Agent-Id": agent_id,
        "Content-Type": "application/json",
    }


# CI's integration job sets this to a PostgreSQL service container; locally SQLite is used.
PG_URL = os.environ.get("EDR_TEST_DATABASE_URL")


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    url = PG_URL or f"sqlite:///{tmp_path / 'test.db'}"
    if PG_URL:
        from edr_server.db import Base, make_engine

        engine = make_engine(PG_URL)
        Base.metadata.drop_all(engine)  # each test starts from an empty schema
        engine.dispose()
    return Settings(
        database_url=url,
        agent_token_hashes={
            AGENT_ID: token_hash(AGENT_TOKEN),
            OTHER_AGENT: token_hash(OTHER_TOKEN),
        },
        baseline_file=BASELINE,
        rate_limit_per_minute=1000,
    )


@pytest.fixture
def client(settings: Settings) -> TestClient:
    with TestClient(create_app(settings, create_tables=True)) as c:
        yield c


def post_scenario(client: TestClient, name: str, batch: int = 200) -> list[dict]:
    """Posts a scenario the way the agent would: events in batches, then its incidents."""
    events = scenario_events(name)
    host = events[0]["host"]
    for i in range(0, len(events), batch):
        r = client.post(
            "/api/v1/events",
            headers=agent_headers(),
            json={"agent_id": AGENT_ID, "host": host, "events": events[i : i + batch]},
        )
        assert r.status_code == 200, r.text
    eng = engine()
    for ev in events:
        eng.process(ev)
    incidents = eng.incidents()
    if incidents:
        r = client.post(
            "/api/v1/incidents",
            headers=agent_headers(),
            content=json.dumps({"agent_id": AGENT_ID, "host": host, "incidents": incidents}),
        )
        assert r.status_code == 200, r.text
    return incidents
