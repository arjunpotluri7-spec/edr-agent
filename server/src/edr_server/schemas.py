"""Pydantic models for the ingest API. Events are validated again by the engine's own checks."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

AGENT_ID = r"^[A-Za-z0-9._-]{1,64}$"
HOST = r"^[A-Za-z0-9._-]{1,255}$"
TS = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"


class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(pattern=AGENT_ID)
    host: str = Field(pattern=HOST)
    events: list[dict[str, Any]] = Field(min_length=1)


class SignalIn(BaseModel):
    model_config = ConfigDict(extra="allow")

    rule_id: str = Field(max_length=64)
    points: int = Field(ge=0, le=100)
    event_id: str = Field(max_length=200)


class IncidentIn(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: str = Field(default="incident", pattern=r"^incident$")
    id: str = Field(pattern=r"^inc-[0-9a-f]{16}$")
    version: int = Field(ge=1, le=1_000_000)
    host: str = Field(pattern=HOST)
    score: int = Field(ge=0, le=100)
    label: str = Field(pattern=r"^(low|medium|high|critical)$")
    first_seen: str = Field(pattern=TS)
    last_seen: str = Field(pattern=TS)
    root: dict[str, Any]
    signals: list[SignalIn] = Field(min_length=1, max_length=500)
    correlations: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    breakdown: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
    attack: list[str] = Field(default_factory=list, max_length=100)
    process_tree: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    evidence: list[dict[str, Any]] = Field(default_factory=list, max_length=100)


class IncidentBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(pattern=AGENT_ID)
    host: str = Field(pattern=HOST)
    incidents: list[IncidentIn] = Field(min_length=1)
