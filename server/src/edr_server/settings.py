"""Server settings, read from environment variables (see .env.example at the repository root)."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_HASH = re.compile(r"[0-9a-f]{64}")
_AGENT_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")


class SettingsError(ValueError):
    """An environment variable has an invalid value."""


def parse_token_hashes(text: str) -> dict[str, str]:
    """``agent-a:<sha256 hex>,agent-b:<sha256 hex>`` -> {agent_id: hash}.

    Only SHA-256 digests of the enrollment tokens are configured on the server, never the tokens.
    """
    out: dict[str, str] = {}
    for item in filter(None, (part.strip() for part in text.split(","))):
        agent_id, sep, digest = item.partition(":")
        if not sep or not _AGENT_ID.fullmatch(agent_id) or not _HASH.fullmatch(digest.lower()):
            raise SettingsError(
                "EDR_AGENT_TOKEN_HASHES entries must look like agent-id:<64 hex chars>"
            )
        out[agent_id] = digest.lower()
    return out


@dataclass(frozen=True)
class Settings:
    database_url: str = "sqlite:///./edr-server.db"
    agent_token_hashes: dict[str, str] = field(default_factory=dict)
    read_token_hash: str | None = None  # optional: require a token for the read API
    rules_dir: Path = _REPO / "rules" / "detections"
    scoring_file: Path = _REPO / "rules" / "scoring.yaml"
    baseline_file: Path | None = None
    max_body_bytes: int = 2 * 1024 * 1024
    max_batch_items: int = 1000
    rate_limit_per_minute: int = 120
    max_events_rescored: int = 20000
    log_level: str = "INFO"
    log_format: str = "text"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env

        def int_env(name: str, default: int, lo: int, hi: int) -> int:
            raw = e.get(name)
            if raw is None or raw == "":
                return default
            try:
                value = int(raw)
            except ValueError as exc:
                raise SettingsError(f"{name} must be an integer") from exc
            if not lo <= value <= hi:
                raise SettingsError(f"{name} must be between {lo} and {hi}")
            return value

        read_hash = e.get("EDR_READ_TOKEN_HASH") or None
        if read_hash is not None and not _HASH.fullmatch(read_hash.lower()):
            raise SettingsError("EDR_READ_TOKEN_HASH must be a SHA-256 hex digest")
        baseline = e.get("EDR_BASELINE_FILE") or None
        return cls(
            database_url=e.get("DATABASE_URL") or cls.database_url,
            agent_token_hashes=parse_token_hashes(e.get("EDR_AGENT_TOKEN_HASHES", "")),
            read_token_hash=read_hash.lower() if read_hash else None,
            rules_dir=Path(e.get("EDR_RULES_DIR") or cls.rules_dir),
            scoring_file=Path(e.get("EDR_SCORING_FILE") or cls.scoring_file),
            baseline_file=Path(baseline) if baseline else None,
            max_body_bytes=int_env("EDR_MAX_BODY_BYTES", cls.max_body_bytes, 1024, 64 * 1024**2),
            max_batch_items=int_env("EDR_MAX_BATCH_ITEMS", cls.max_batch_items, 1, 10000),
            rate_limit_per_minute=int_env("EDR_RATE_LIMIT_PER_MINUTE", 120, 1, 100000),
            max_events_rescored=int_env("EDR_MAX_EVENTS_RESCORED", 20000, 100, 1000000),
            log_level=(e.get("EDR_LOG_LEVEL") or "INFO").upper(),
            log_format=e.get("EDR_LOG_FORMAT") or "text",
        )
