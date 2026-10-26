"""SQLAlchemy 2 models. PostgreSQL in deployment (see docker-compose.yml), SQLite for tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

JsonType = JSON().with_variant(JSONB(), "postgresql")
# SQLite only auto-increments INTEGER PRIMARY KEY, so BigInteger becomes Integer there.
BigId = BigInteger().with_variant(Integer(), "sqlite")


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    agent_id: Mapped[str] = mapped_column(String(64))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    event_count: Mapped[int] = mapped_column(Integer, default=0)


class EventRow(Base):
    __tablename__ = "events"
    __table_args__ = (Index("ix_events_host_ts", "host", "ts_ms", "seq"),)

    seq: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(200), unique=True)
    host: Mapped[str] = mapped_column(String(255))
    ts_ms: Mapped[int] = mapped_column(BigInteger)
    type: Mapped[str] = mapped_column(String(32))
    pid: Mapped[int] = mapped_column(BigInteger)
    image: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict[str, Any]] = mapped_column(JsonType)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IncidentRow(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_score", "score"), Index("ix_incidents_host", "host"))

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    host: Mapped[str] = mapped_column(String(255))
    agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # What the agent reported (latest version) ...
    agent_version: Mapped[int] = mapped_column(Integer, default=0)
    agent_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    agent_detail: Mapped[dict[str, Any] | None] = mapped_column(JsonType, nullable=True)
    # ... and what the server computed from the stored telemetry with the same rules.
    server_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    server_detail: Mapped[dict[str, Any] | None] = mapped_column(JsonType, nullable=True)
    # Display fields: server values when available, else the agent's.
    score: Mapped[int] = mapped_column(Integer)
    label: Mapped[str] = mapped_column(String(16))
    first_seen: Mapped[str] = mapped_column(String(32))
    last_seen: Mapped[str] = mapped_column(String(32))
    root_image: Mapped[str] = mapped_column(Text, default="")
    root_pid: Mapped[int] = mapped_column(BigInteger, default=0)
    signal_count: Mapped[int] = mapped_column(Integer, default=0)
    attack: Mapped[list[str]] = mapped_column(JsonType, default=list)
    score_mismatch: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        kwargs: dict[str, Any] = {"connect_args": {"check_same_thread": False}}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool
        engine = create_engine(url, **kwargs)

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        return engine
    return create_engine(url, pool_pre_ping=True)


def make_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, expire_on_commit=False)
