"""FastAPI application: agent ingest (token auth), re-scoring and the dashboard's read API."""

# No `from __future__ import annotations` here: FastAPI resolves the Annotated dependency
# aliases defined inside create_app() at runtime.

from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from edr_server import __version__
from edr_server.db import (
    Base,
    EventRow,
    Host,
    IncidentRow,
    make_engine,
    make_session_factory,
    utcnow,
)
from edr_server.engine.scorer import EventError, validate_event
from edr_server.logsetup import get_logger
from edr_server.rescoring import RuleBundle, apply_display, rescore_host
from edr_server.schemas import EventBatch, IncidentBatch
from edr_server.security import (
    BodySizeLimit,
    RateLimiter,
    authenticate_agent,
    check_read_token,
)
from edr_server.settings import Settings

log = get_logger("api")


def create_app(settings: Settings | None = None, *, create_tables: bool = False) -> FastAPI:
    settings = settings or Settings.from_env()
    engine = make_engine(settings.database_url)
    if create_tables:
        Base.metadata.create_all(engine)
    sessions = make_session_factory(engine)
    bundle = RuleBundle.load(settings)
    limiter = RateLimiter(settings.rate_limit_per_minute)

    app = FastAPI(title="EDR Agent server", version=__version__, docs_url="/docs", redoc_url=None)
    app.state.settings = settings
    app.state.db_engine = engine
    app.state.bundle = bundle
    app.add_middleware(BodySizeLimit, max_bytes=settings.max_body_bytes)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def db():
        with sessions() as session:
            yield session

    DB = Annotated[Session, Depends(db)]

    def agent(request: Request) -> str:
        agent_id = authenticate_agent(request, settings.agent_token_hashes)
        if not limiter.check(agent_id):
            raise HTTPException(
                status_code=429, detail="rate limit exceeded", headers={"Retry-After": "60"}
            )
        return agent_id

    def reader(request: Request) -> None:
        check_read_token(request, settings.read_token_hash)

    Agent = Annotated[str, Depends(agent)]

    def check_batch(agent_id: str, body_agent: str, count: int) -> None:
        if body_agent != agent_id:
            raise HTTPException(status_code=403, detail="agent_id does not match credentials")
        if count > settings.max_batch_items:
            raise HTTPException(
                status_code=422, detail=f"at most {settings.max_batch_items} items per batch"
            )

    def touch_host(session: Session, name: str, agent_id: str, new_events: int) -> None:
        host = session.scalar(select(Host).where(Host.name == name))
        if host is None:
            host = Host(name=name, agent_id=agent_id, event_count=0)
            session.add(host)
        host.agent_id = agent_id
        host.last_seen = utcnow()
        host.event_count = (host.event_count or 0) + new_events

    @app.get("/healthz")
    def healthz(session: DB) -> dict[str, str]:
        session.execute(text("SELECT 1"))
        return {"status": "ok", "version": __version__}

    @app.post("/api/v1/events")
    def ingest_events(batch: EventBatch, agent_id: Agent, session: DB) -> dict[str, Any]:
        check_batch(agent_id, batch.agent_id, len(batch.events))
        validated = []
        for i, raw in enumerate(batch.events):
            try:
                ev = validate_event(raw)
            except EventError as exc:
                raise HTTPException(status_code=422, detail=f"events[{i}]: {exc}") from exc
            if ev["host"] != batch.host:
                raise HTTPException(status_code=422, detail=f"events[{i}]: host differs from batch")
            if len(ev["id"]) > 200:
                raise HTTPException(status_code=422, detail=f"events[{i}]: id too long")
            validated.append((raw, ev))
        ids = [ev["id"] for _, ev in validated]
        existing = set(session.scalars(select(EventRow.id).where(EventRow.id.in_(ids))).all())
        new = 0
        seen: set[str] = set()
        for raw, ev in validated:
            if ev["id"] in existing or ev["id"] in seen:
                continue
            seen.add(ev["id"])
            session.add(
                EventRow(
                    id=ev["id"],
                    host=ev["host"],
                    ts_ms=ev["_ts_ms"],
                    type=ev["type"],
                    pid=ev["pid"],
                    image=ev.get("image", ""),
                    data=raw,
                )
            )
            new += 1
        touch_host(session, batch.host, agent_id, new)
        session.flush()
        result = rescore_host(session, bundle, batch.host, settings.max_events_rescored)
        session.commit()
        log.info(
            "events ingested",
            extra={
                "agent_id": agent_id,
                "host": batch.host,
                "accepted": new,
                "duplicates": len(ids) - new,
            },
        )
        return {
            "accepted": new,
            "duplicates": len(ids) - new,
            "server_incidents": result["incidents"],
        }

    @app.post("/api/v1/incidents")
    def ingest_incidents(batch: IncidentBatch, agent_id: Agent, session: DB) -> dict[str, Any]:
        check_batch(agent_id, batch.agent_id, len(batch.incidents))
        stored = 0
        stale = 0
        for inc in batch.incidents:
            if inc.host != batch.host:
                raise HTTPException(status_code=422, detail="incident host differs from batch")
            row = session.get(IncidentRow, inc.id)
            if row is None:
                row = IncidentRow(
                    id=inc.id,
                    host=inc.host,
                    agent_version=0,
                    first_seen="",
                    last_seen="",
                    score=0,
                    label="low",
                )
                session.add(row)
            if inc.version <= (row.agent_version or 0):
                stale += 1  # duplicate or older version: idempotent no-op
                continue
            row.agent_id = agent_id
            row.agent_version = inc.version
            row.agent_score = inc.score
            row.agent_detail = inc.model_dump()
            apply_display(row)
            stored += 1
        touch_host(session, batch.host, agent_id, 0)
        session.commit()
        return {"stored": stored, "unchanged": stale}

    def incident_summary(row: IncidentRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "host": row.host,
            "score": row.score,
            "label": row.label,
            "agent_score": row.agent_score,
            "server_score": row.server_score,
            "score_mismatch": row.score_mismatch,
            "first_seen": row.first_seen,
            "last_seen": row.last_seen,
            "root_image": row.root_image,
            "root_pid": row.root_pid,
            "signal_count": row.signal_count,
            "attack": row.attack,
        }

    @app.get("/api/v1/hosts", dependencies=[Depends(reader)])
    def hosts(session: DB) -> list[dict[str, Any]]:
        agg = {
            name: (count, top)
            for name, count, top in session.execute(
                select(IncidentRow.host, func.count(), func.max(IncidentRow.score)).group_by(
                    IncidentRow.host
                )
            )
        }
        out = []
        for h in session.scalars(select(Host).order_by(Host.name)).all():
            count, top = agg.get(h.name, (0, None))
            out.append(
                {
                    "name": h.name,
                    "agent_id": h.agent_id,
                    "first_seen": h.first_seen.isoformat(),
                    "last_seen": h.last_seen.isoformat(),
                    "event_count": h.event_count,
                    "incident_count": count,
                    "max_score": top,
                }
            )
        return out

    @app.get("/api/v1/incidents", dependencies=[Depends(reader)])
    def incidents(
        session: DB,
        min_score: Annotated[int, Query(ge=0, le=100)] = 0,
        host: Annotated[str | None, Query(max_length=255)] = None,
        label: Annotated[str | None, Query(pattern=r"^(low|medium|high|critical)$")] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        q = select(IncidentRow).where(IncidentRow.score >= min_score)
        if host:
            q = q.where(IncidentRow.host == host)
        if label:
            q = q.where(IncidentRow.label == label)
        total = session.scalar(select(func.count()).select_from(q.subquery()))
        rows = session.scalars(
            q.order_by(IncidentRow.score.desc(), IncidentRow.last_seen.desc(), IncidentRow.id)
            .limit(limit)
            .offset(offset)
        ).all()
        return {"total": total, "items": [incident_summary(r) for r in rows]}

    @app.get("/api/v1/incidents/{incident_id}", dependencies=[Depends(reader)])
    def incident(incident_id: str, session: DB) -> dict[str, Any]:
        row = session.get(IncidentRow, incident_id)
        if row is None:
            raise HTTPException(status_code=404, detail="incident not found")
        detail = row.server_detail or row.agent_detail or {}
        out = incident_summary(row)
        out.update(
            {
                "signals": detail.get("signals", []),
                "correlations": detail.get("correlations", []),
                "breakdown": detail.get("breakdown", []),
                "process_tree": detail.get("process_tree", []),
                "evidence": detail.get("evidence", []),
                "agent_detail": row.agent_detail,
                "server_detail": row.server_detail,
            }
        )
        return out

    @app.get("/api/v1/stats", dependencies=[Depends(reader)])
    def stats(session: DB) -> dict[str, Any]:
        by_label = dict(
            session.execute(
                select(IncidentRow.label, func.count()).group_by(IncidentRow.label)
            ).all()
        )
        by_type = dict(
            session.execute(select(EventRow.type, func.count()).group_by(EventRow.type)).all()
        )
        return {
            "hosts": session.scalar(select(func.count()).select_from(Host)),
            "events": session.scalar(select(func.count()).select_from(EventRow)),
            "incidents": session.scalar(select(func.count()).select_from(IncidentRow)),
            "incidents_by_label": by_label,
            "events_by_type": by_type,
            "score_mismatches": session.scalar(
                select(func.count()).select_from(IncidentRow).where(IncidentRow.score_mismatch)
            ),
            "incident_threshold": bundle.scoring.incident_threshold,
        }

    @app.exception_handler(ValueError)
    async def value_error(_request: Request, exc: ValueError) -> JSONResponse:
        log.warning("bad request", extra={"error": str(exc)[:200]})
        return JSONResponse(status_code=400, content={"detail": "bad request"})

    return app
