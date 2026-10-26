#!/usr/bin/env python3
"""Smoke test for a running docker compose stack (used in CI).

Writes an agent-style spool file for every sample scenario (events and incidents computed by
the Python engine), forwards it with edr_server.forwarder to http://127.0.0.1:8000, and checks
the read API through both the server and the dashboard's nginx proxy.

    EDR_AGENT_TOKEN=<token> PYTHONPATH=server/src python3 scripts/compose_smoke.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "server" / "src"))

from edr_server.engine.replay import build_engine, read_jsonl  # noqa: E402
from edr_server.forwarder import forward, urllib_poster  # noqa: E402

SERVER = os.environ.get("EDR_SMOKE_SERVER", "http://127.0.0.1:8000")
DASHBOARD = "http://127.0.0.1:8080"
AGENT_ID = os.environ.get("EDR_SMOKE_AGENT_ID", "ci-agent")


def get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310 - fixed localhost URLs
        return json.loads(resp.read())


def wait_for(url: str, seconds: int = 90) -> None:
    deadline = time.time() + seconds
    while True:
        try:
            get(url)
            return
        except OSError:
            if time.time() > deadline:
                raise
            time.sleep(2)


def main() -> int:
    token = os.environ["EDR_AGENT_TOKEN"]
    wait_for(f"{SERVER}/healthz")
    print("healthz:", get(f"{SERVER}/healthz"))
    engine = build_engine(REPO / "rules" / "detections", REPO / "rules" / "scoring.yaml", None)
    with tempfile.TemporaryDirectory() as tmp:
        spool = Path(tmp) / "spool.jsonl"
        with spool.open("w") as out:
            for path in sorted((REPO / "samples").glob("scenario_*.jsonl")):
                events = list(read_jsonl(path))
                host = events[0]["host"]
                for ev in events:
                    engine.process(ev)
                body = {"agent_id": AGENT_ID, "host": host, "events": events}
                out.write(json.dumps({"endpoint": "/api/v1/events", "body": body}) + "\n")
                incidents = [i for i in engine.incidents() if i["host"] == host]
                if incidents:
                    body = {"agent_id": AGENT_ID, "host": host, "incidents": incidents}
                    out.write(json.dumps({"endpoint": "/api/v1/incidents", "body": body}) + "\n")
        result = forward(spool, SERVER, AGENT_ID, token, urllib_poster(None))
    print("forwarded batches:", result["sent"])
    listing = get(f"{SERVER}/api/v1/incidents")
    scores = [(i["host"], i["score"], i["label"], i["score_mismatch"]) for i in listing["items"]]
    print("incidents:", scores)
    # The container runs without the sample baseline, so first-seen destinations add
    # anomalous-outbound signals; the expectation is computed with the same (empty) baseline.
    expected = sorted(((i["host"], i["score"]) for i in engine.incidents()),
                      key=lambda x: (-x[1], x[0]))
    got = sorted(((s[0], s[1]) for s in scores), key=lambda x: (-x[1], x[0]))
    assert got == expected, (got, expected)
    assert ("WS-ALICE-01", 100) in got and ("WS-BOB-02", 60) in got, got
    assert not any(s[3] for s in scores), "agent and server scores disagree"
    if os.environ.get("EDR_SMOKE_SKIP_DASHBOARD") == "1":  # local runs without the compose stack
        print("dashboard checks skipped")
        return 0
    via_proxy = get(f"{DASHBOARD}/api/v1/stats")
    print("stats via dashboard proxy:", via_proxy)
    assert via_proxy["incidents"] == len(expected)
    with urllib.request.urlopen(f"{DASHBOARD}/", timeout=10) as resp:  # noqa: S310
        assert b'<div id="root">' in resp.read()
    print("compose smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
