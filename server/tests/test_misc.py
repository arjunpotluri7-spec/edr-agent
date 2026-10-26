"""Settings parsing, migrations, forwarder and logging."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

from edr_server.cli import main as cli_main
from edr_server.cli import migrate
from edr_server.forwarder import ForwardError, check_url, forward
from edr_server.logsetup import JsonFormatter
from edr_server.settings import Settings, SettingsError, parse_token_hashes


def test_token_hashes_parse_and_reject_raw_tokens() -> None:
    digest = "a" * 64
    assert parse_token_hashes(f"ws-1:{digest}, ws-2:{digest.upper()}") == {
        "ws-1": digest,
        "ws-2": digest,
    }
    with pytest.raises(SettingsError):
        parse_token_hashes("ws-1:not-a-hash")
    with pytest.raises(SettingsError):
        Settings.from_env({"EDR_MAX_BODY_BYTES": "lots"})
    s = Settings.from_env({"DATABASE_URL": "sqlite://", "EDR_RATE_LIMIT_PER_MINUTE": "7"})
    assert (s.database_url, s.rate_limit_per_minute) == ("sqlite://", 7)


def test_alembic_migration_creates_the_schema(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'm.db'}"
    migrate(Settings(database_url=url))
    tables = set(inspect(create_engine(url)).get_table_names())
    assert {"hosts", "events", "incidents", "alembic_version"} <= tables


def test_hash_token_cli(monkeypatch, capsys) -> None:
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert cli_main(["hash-token"]) == 2
    monkeypatch.setattr("sys.stdin", io.StringIO("x" * 32 + "\n"))
    assert cli_main(["hash-token"]) == 0
    assert len(capsys.readouterr().out.strip()) == 64


def test_forwarder_posts_in_order_and_resumes(tmp_path: Path) -> None:
    spool = tmp_path / "spool.jsonl"
    lines = [
        {"endpoint": "/api/v1/events", "body": {"n": 1}},
        {"endpoint": "/api/v1/incidents", "body": {"n": 2}},
    ]
    spool.write_text("".join(json.dumps(x) + "\n" for x in lines) + '{"partial":')
    calls: list[tuple[str, bytes, dict]] = []
    statuses = iter([200, 503, 200])

    def post(url: str, body: bytes, headers: dict) -> int:
        calls.append((url, body, headers))
        return next(statuses)

    with pytest.raises(ForwardError, match="503"):
        forward(spool, "https://edr.example.com", "ws-1", "tok", post)
    assert (tmp_path / "spool.jsonl.offset").read_text() == str(len(json.dumps(lines[0])) + 1)
    result = forward(spool, "https://edr.example.com", "ws-1", "tok", post)
    assert result["sent"] == 1  # resumed at the second line; the partial line is left alone
    assert calls[0][0] == "https://edr.example.com/api/v1/events"
    assert calls[2][0] == "https://edr.example.com/api/v1/incidents"
    assert calls[0][2]["Authorization"] == "Bearer tok"
    assert calls[0][2]["X-Agent-Id"] == "ws-1"


def test_forwarder_url_rules(tmp_path: Path) -> None:
    assert check_url("https://edr.example.com:8443") == "https://edr.example.com:8443"
    assert check_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"
    for bad in [
        "http://edr.example.com",
        "ftp://x",
        "https://u:p@x.example.com",
        "https://x.example.com/api",
    ]:
        with pytest.raises(ForwardError):
            check_url(bad)
    spool = tmp_path / "s.jsonl"
    spool.write_text(json.dumps({"endpoint": "/admin", "body": {}}) + "\n")
    with pytest.raises(ForwardError, match="unexpected"):
        forward(spool, "https://x.example.com", "a", "t", lambda *_: 200)


def test_json_log_format_has_no_secrets() -> None:
    rec = logging.LogRecord(
        "edr_server.x", logging.WARNING, "f", 1, "rejected agent request", None, None
    )
    rec.agent_id = "ws-1"
    out = json.loads(JsonFormatter().format(rec))
    assert out["msg"] == "rejected agent request"
    assert out["agent_id"] == "ws-1"
    assert set(out) == {"ts", "level", "logger", "msg", "agent_id"}
