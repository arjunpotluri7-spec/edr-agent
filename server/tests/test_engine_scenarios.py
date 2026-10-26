"""Each synthetic scenario produces the outcome described in samples/README.md."""

from __future__ import annotations

from .conftest import engine, scenario_events


def run(name: str):
    eng = engine()
    for ev in scenario_events(name):
        eng.process(ev)
    return eng.incidents(), eng.tree_summaries()


def test_benign_admin_day() -> None:
    incidents, trees = run("scenario_1_benign_admin_day")
    assert incidents == []
    assert trees == []


def test_phishing_chain() -> None:
    incidents, _ = run("scenario_2_phishing_chain")
    assert len(incidents) == 1
    inc = incidents[0]
    assert (inc["score"], inc["label"], inc["host"]) == (100, "critical", "WS-ALICE-01")
    assert [c["id"] for c in inc["correlations"]] == [
        "office-macro-chain",
        "encoded-ps-then-network",
    ]
    assert [b["kind"] for b in inc["breakdown"]][-3:] == ["multiplier", "multiplier", "cap"]
    assert any(
        e.get("decoded_command") == "Write-Output 'edr-agent demo: simulated download cradle'"
        for e in inc["evidence"]
    )


def test_runkey_persistence() -> None:
    incidents, _ = run("scenario_3_runkey_persistence")
    assert [(i["score"], i["label"]) for i in incidents] == [(55, "medium")]


def test_lolbin_download() -> None:
    incidents, _ = run("scenario_4_lolbin_download")
    assert [(i["score"], i["label"]) for i in incidents] == [(60, "high")]


def test_noise_never_becomes_an_incident() -> None:
    incidents, trees = run("scenario_5_low_severity_noise")
    assert incidents == []
    assert len(trees) == 4
    assert max(t["score"] for t in trees) <= 20
    assert sum(t["signals"] for t in trees) == 13


def test_window_expiry_and_ordering() -> None:
    base = {"host": "H", "source": "replay"}
    ps = dict(
        base,
        id="1",
        ts="2026-10-20T10:00:00.000Z",
        type="process_create",
        pid=200,
        image="C:\\x\\powershell.exe",
        command_line="powershell -enc aABpAA==",
    )
    late = dict(
        base,
        id="2",
        ts="2026-10-20T10:11:00.000Z",
        type="network_connect",
        pid=200,
        image="C:\\x\\powershell.exe",
        dest_ip="203.0.113.50",
        dest_port=443,
    )
    eng = engine(baseline=False)
    eng.process(ps)
    assert eng.process(late) == []
    assert [t["score"] for t in eng.tree_summaries()] == [40, 35]
    eng = engine(baseline=False)
    eng.process(ps)
    updates = eng.process(dict(late, ts="2026-10-20T10:09:59.000Z"))
    assert [u["score"] for u in updates] == [100]


def test_one_rule_repeating_is_not_an_incident_but_critical_alone_is() -> None:
    def net(i: int, ip: str) -> dict:
        return {
            "id": f"n{i}",
            "ts": f"2026-10-20T10:00:0{i}.000Z",
            "host": "H",
            "pid": 300,
            "type": "network_connect",
            "image": "C:\\Apps\\browser.exe",
            "dest_ip": ip,
            "dest_port": 443,
        }

    eng = engine(baseline=False)
    eng.process(net(0, "198.51.100.20"))
    assert eng.process(net(1, "198.51.100.21")) == []
    assert [(t["score"], t["incident_id"]) for t in eng.tree_summaries()] == [(52, None)]
    access = {
        "id": "a1",
        "ts": "2026-10-20T10:00:00.000Z",
        "host": "H",
        "pid": 900,
        "type": "process_access",
        "image": "C:\\Users\\u\\Downloads\\tool.exe",
        "target_image": "C:\\Windows\\system32\\lsass.exe",
        "granted_access": "0x1010",
    }
    assert [u["score"] for u in engine(baseline=False).process(access)] == [60]
