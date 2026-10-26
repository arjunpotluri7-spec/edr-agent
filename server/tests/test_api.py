"""Ingest auth, validation, idempotency, limits and the read API."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from edr_server.app import create_app
from edr_server.settings import Settings

from .conftest import (
    AGENT_ID,
    OTHER_AGENT,
    OTHER_TOKEN,
    agent_headers,
    engine,
    post_scenario,
    scenario_events,
)

EVENT = {
    "id": "e-1",
    "ts": "2026-10-20T10:00:00.000Z",
    "host": "WS-T",
    "type": "dns_query",
    "pid": 1,
    "image": "C:\\x.exe",
    "query_name": "example.com",
}


def batch(events=None, agent=AGENT_ID, host="WS-T"):
    return {"agent_id": agent, "host": host, "events": events or [EVENT]}


def test_healthz(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_missing_and_bad_tokens_get_401(client: TestClient) -> None:
    assert client.post("/api/v1/events", json=batch()).status_code == 401
    r = client.post("/api/v1/events", json=batch(), headers=agent_headers(token="wrong-token"))
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
    r = client.post(
        "/api/v1/events", json=batch(), headers=agent_headers(agent_id="unknown", token="whatever")
    )
    assert r.status_code == 401
    r = client.post(
        "/api/v1/events",
        json=batch(),
        headers={"Authorization": "Basic abc", "X-Agent-Id": AGENT_ID},
    )
    assert r.status_code == 401
    # A valid token for a different agent does not work for this agent id.
    r = client.post(
        "/api/v1/events", json=batch(), headers=agent_headers(agent_id=AGENT_ID, token=OTHER_TOKEN)
    )
    assert r.status_code == 401
    assert client.post("/api/v1/incidents", json={}).status_code in (401, 422)


def test_agent_id_must_match_credentials(client: TestClient) -> None:
    r = client.post("/api/v1/events", json=batch(agent=OTHER_AGENT), headers=agent_headers())
    assert r.status_code == 403


def test_validation_errors(client: TestClient) -> None:
    h = agent_headers()
    assert client.post("/api/v1/events", json={"agent_id": AGENT_ID}, headers=h).status_code == 422
    bad_ts = dict(EVENT, ts="yesterday")
    r = client.post("/api/v1/events", json=batch([bad_ts]), headers=h)
    assert r.status_code == 422
    assert "bad timestamp" in r.json()["detail"]
    bad_type = dict(EVENT, type="keylogger")
    assert client.post("/api/v1/events", json=batch([bad_type]), headers=h).status_code == 422
    wrong_host = dict(EVENT, host="OTHER")
    assert client.post("/api/v1/events", json=batch([wrong_host]), headers=h).status_code == 422
    str_pid = dict(EVENT, pid="1")
    assert client.post("/api/v1/events", json=batch([str_pid]), headers=h).status_code == 422
    r = client.post(
        "/api/v1/incidents",
        headers=h,
        json={"agent_id": AGENT_ID, "host": "WS-T", "incidents": [{"id": "x"}]},
    )
    assert r.status_code == 422
    r = client.post("/api/v1/events", content=b"{not json", headers=h)
    assert r.status_code == 422


def test_event_ingest_is_idempotent(client: TestClient) -> None:
    h = agent_headers()
    first = client.post("/api/v1/events", json=batch([EVENT, EVENT]), headers=h).json()
    assert (first["accepted"], first["duplicates"]) == (1, 1)
    again = client.post("/api/v1/events", json=batch(), headers=h).json()
    assert (again["accepted"], again["duplicates"]) == (0, 1)
    assert client.get("/api/v1/stats").json()["events"] == 1


def test_incident_versions_only_move_forward(client: TestClient) -> None:
    incidents = post_scenario(client, "scenario_4_lolbin_download")
    h = agent_headers()
    body = {"agent_id": AGENT_ID, "host": "WS-BOB-02", "incidents": incidents}
    r = client.post("/api/v1/incidents", headers=h, content=json.dumps(body))
    assert r.json() == {"stored": 0, "unchanged": 1}
    older = dict(incidents[0], version=incidents[0]["version"] - 1 or 1, score=1)
    r = client.post(
        "/api/v1/incidents", headers=h, content=json.dumps(dict(body, incidents=[older]))
    )
    assert r.json()["stored"] == 0
    detail = client.get(f"/api/v1/incidents/{incidents[0]['id']}").json()
    assert detail["agent_score"] == 60


def test_body_size_and_batch_limits(settings: Settings) -> None:
    small = Settings(**{**settings.__dict__, "max_body_bytes": 2048, "max_batch_items": 2})
    with TestClient(create_app(small, create_tables=True)) as c:
        h = agent_headers()
        big = batch([dict(EVENT, id=f"e-{i}", query_name="x" * 500) for i in range(5)])
        assert c.post("/api/v1/events", json=big, headers=h).status_code == 413
        three = batch([dict(EVENT, id=f"e-{i}") for i in range(3)])
        r = c.post("/api/v1/events", json=three, headers=h)
        assert r.status_code == 422
        assert "at most 2" in r.json()["detail"]

        def chunks():
            yield b'{"agent_id":"test-agent","host":"WS-T","events":['
            for _ in range(100):
                yield b'{"id":"x","ts":"2026-10-20T10:00:00.000Z","host":"WS-T"},'
            yield b"]}"

        r = c.post("/api/v1/events", content=chunks(), headers=h)
        assert r.status_code == 413


def test_rate_limit(settings: Settings) -> None:
    limited = Settings(**{**settings.__dict__, "rate_limit_per_minute": 3})
    with TestClient(create_app(limited, create_tables=True)) as c:
        codes = [
            c.post("/api/v1/events", json=batch(), headers=agent_headers()).status_code
            for _ in range(5)
        ]
    assert codes == [200, 200, 200, 429, 429]


def test_queries_after_replaying_all_scenarios(client: TestClient) -> None:
    for name in (
        "scenario_1_benign_admin_day",
        "scenario_2_phishing_chain",
        "scenario_3_runkey_persistence",
        "scenario_4_lolbin_download",
        "scenario_5_low_severity_noise",
    ):
        post_scenario(client, name)
    hosts = client.get("/api/v1/hosts").json()
    assert [h["name"] for h in hosts] == [
        "SRV-FILES-01",
        "WS-ALICE-01",
        "WS-BOB-02",
        "WS-CAROL-03",
        "WS-DAVE-04",
    ]
    by_name = {h["name"]: h for h in hosts}
    assert by_name["WS-ALICE-01"]["max_score"] == 100
    assert by_name["SRV-FILES-01"]["incident_count"] == 0

    listing = client.get("/api/v1/incidents").json()
    assert listing["total"] == 3
    assert [i["score"] for i in listing["items"]] == [100, 60, 55]
    assert all(not i["score_mismatch"] for i in listing["items"])
    assert all(i["agent_score"] == i["server_score"] for i in listing["items"])
    assert client.get("/api/v1/incidents?min_score=60").json()["total"] == 2
    assert client.get("/api/v1/incidents?host=WS-CAROL-03").json()["items"][0]["score"] == 55
    assert client.get("/api/v1/incidents?label=high").json()["total"] == 1
    assert client.get("/api/v1/incidents?min_score=101").status_code == 422

    top = listing["items"][0]
    detail = client.get(f"/api/v1/incidents/{top['id']}").json()
    assert detail["host"] == "WS-ALICE-01"
    assert {"signals", "breakdown", "process_tree", "evidence", "correlations"} <= set(detail)
    assert len(detail["process_tree"]) == 3
    assert client.get("/api/v1/incidents/inc-0000000000000000").status_code == 404

    stats = client.get("/api/v1/stats").json()
    assert stats["hosts"] == 5
    assert stats["incidents"] == 3
    assert stats["incidents_by_label"] == {"critical": 1, "high": 1, "medium": 1}
    assert stats["score_mismatches"] == 0


def test_server_rescoring_flags_a_tampered_agent_score(client: TestClient) -> None:
    events = scenario_events("scenario_3_runkey_persistence")
    h = agent_headers()
    client.post(
        "/api/v1/events",
        headers=h,
        json={"agent_id": AGENT_ID, "host": "WS-CAROL-03", "events": events},
    )
    eng = engine()
    for ev in events:
        eng.process(ev)
    inc = dict(eng.incidents()[0], score=12, label="low")  # agent claims a low score
    client.post(
        "/api/v1/incidents",
        headers=h,
        content=json.dumps({"agent_id": AGENT_ID, "host": "WS-CAROL-03", "incidents": [inc]}),
    )
    row = client.get(f"/api/v1/incidents/{inc['id']}").json()
    assert row["agent_score"] == 12
    assert row["server_score"] == 55
    assert row["score"] == 55  # the server's own score is displayed
    assert row["score_mismatch"] is True


def test_server_finds_incidents_the_agent_did_not_report(client: TestClient) -> None:
    events = scenario_events("scenario_2_phishing_chain")
    r = client.post(
        "/api/v1/events",
        headers=agent_headers(),
        json={"agent_id": AGENT_ID, "host": "WS-ALICE-01", "events": events},
    )
    assert r.json()["server_incidents"] == 1
    item = client.get("/api/v1/incidents").json()["items"][0]
    assert item["agent_score"] is None
    assert item["server_score"] == 100


def test_optional_read_token(settings: Settings) -> None:
    from edr_server.security import token_hash

    locked = Settings(**{**settings.__dict__, "read_token_hash": token_hash("dashboard-test")})
    with TestClient(create_app(locked, create_tables=True)) as c:
        assert c.get("/api/v1/incidents").status_code == 401
        ok = c.get("/api/v1/incidents", headers={"Authorization": "Bearer dashboard-test"})
        assert ok.status_code == 200
        assert c.get("/healthz").status_code == 200
