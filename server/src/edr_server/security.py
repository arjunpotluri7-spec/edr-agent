"""Agent authentication, body size limit and per-agent rate limiting."""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import deque

from fastapi import HTTPException, Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from edr_server.logsetup import get_logger

log = get_logger("security")
_DUMMY_HASH = "0" * 64


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def authenticate_agent(request: Request, hashes: dict[str, str]) -> str:
    """Returns the agent id, or raises 401. Constant-time comparison of token digests."""
    agent_id = request.headers.get("x-agent-id", "")
    token = bearer_token(request)
    expected = hashes.get(agent_id, _DUMMY_HASH)
    presented = token_hash(token) if token is not None else "x" * 64
    # Always compare (even for unknown agents) so timing does not reveal which ids exist.
    ok = hmac.compare_digest(expected, presented) and agent_id in hashes
    if not ok or token is None:
        log.warning("rejected agent request", extra={"agent_id": agent_id[:64] or "-"})
        raise HTTPException(
            status_code=401,
            detail="invalid or missing agent credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return agent_id


def check_read_token(request: Request, read_hash: str | None) -> None:
    if read_hash is None:
        return
    token = bearer_token(request)
    presented = token_hash(token) if token is not None else ""
    if token is None or not hmac.compare_digest(read_hash, presented):
        raise HTTPException(
            status_code=401, detail="read token required", headers={"WWW-Authenticate": "Bearer"}
        )


class RateLimiter:
    """Sliding one-minute window per key (agent id). In memory, per process."""

    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str, now: float | None = None) -> bool:
        t = time.monotonic() if now is None else now
        with self._lock:
            window = self._hits.setdefault(key, deque())
            while window and window[0] <= t - 60:
                window.popleft()
            if len(window) >= self.per_minute:
                return False
            window.append(t)
            return True


class BodySizeLimit:
    """ASGI middleware: rejects request bodies larger than max_bytes with 413, whether or not
    Content-Length is sent (chunked bodies are counted as they arrive)."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_big = int(value) > self.max_bytes
                except ValueError:
                    too_big = True
                if too_big:
                    await _reject(send)
                    return
        # Read the whole body first (it is capped, so buffering is bounded), then replay it to
        # the app. Rejecting before the app runs keeps framework error handling out of the way.
        chunks: list[bytes] = []
        received = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                await self.app(scope, _replay([message]), send)
                return
            body = message.get("body", b"")
            received += len(body)
            if received > self.max_bytes:
                await _reject(send)
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break
        await self.app(
            scope,
            _replay(
                [{"type": "http.request", "body": b"".join(chunks), "more_body": False}], receive
            ),
            send,
        )


def _replay(messages: list[Message], then: Receive | None = None) -> Receive:
    pending = list(messages)

    async def receive() -> Message:
        if pending:
            return pending.pop(0)
        if then is not None:
            return await then()
        return {"type": "http.disconnect"}

    return receive


async def _reject(send: Send) -> None:
    body = b'{"detail":"request body too large"}'
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
