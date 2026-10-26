"""Forward an agent spool file to the server over HTTPS (the non-Windows output path).

The C++ agent's SpoolTransport appends one JSON object per line:
    {"endpoint": "/api/v1/events", "body": {...}}
This forwarder posts each body to <server_url><endpoint> with the agent's enrollment token,
remembers how far it got in <spool>.offset, and stops at the first failure so nothing is
skipped. TLS certificates are verified (system trust store, or --ca-file); plain http is only
accepted for 127.0.0.1 / localhost / [::1].

    EDR_AGENT_TOKEN=... python -m edr_server.forwarder --spool edr-agent-spool.jsonl \\
        --server-url https://edr.example.com --agent-id ws-alice-01
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from edr_server.logsetup import get_logger, setup_logging

log = get_logger("forwarder")
ALLOWED_ENDPOINTS = {"/api/v1/events", "/api/v1/incidents"}
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}

Poster = Callable[[str, bytes, dict[str, str]], int]


class ForwardError(RuntimeError):
    pass


def check_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ForwardError("server URL must be https://host[:port]")
    if parts.username or parts.password:
        raise ForwardError("server URL must not contain credentials")
    if parts.scheme == "http" and parts.hostname not in LOCAL_HOSTS:
        raise ForwardError("plain http is only allowed for localhost; use https")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ForwardError("server URL must not have a path or query")
    return f"{parts.scheme}://{parts.netloc}"


def urllib_poster(ca_file: str | None, timeout: float = 15.0) -> Poster:
    context = ssl.create_default_context(cafile=ca_file)  # verification on, hostname checked

    def post(url: str, body: bytes, headers: dict[str, str]) -> int:
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:  # noqa: S310
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.warning("request failed", extra={"error": str(exc)[:200]})
            return 0

    return post


def forward(spool: Path, base_url: str, agent_id: str, token: str, post: Poster) -> dict[str, int]:
    """Posts every not-yet-forwarded line. Returns counts; raises ForwardError on failure."""
    base = check_url(base_url)
    offset_file = spool.with_name(spool.name + ".offset")
    offset = int(offset_file.read_text().strip() or 0) if offset_file.exists() else 0
    sent = 0
    with spool.open("rb") as handle:
        handle.seek(offset)
        for raw in handle:
            if not raw.endswith(b"\n"):
                break  # partial line still being written by the agent
            line = json.loads(raw)
            endpoint = line.get("endpoint")
            if endpoint not in ALLOWED_ENDPOINTS or not isinstance(line.get("body"), dict):
                raise ForwardError(f"unexpected spool line at byte {offset}")
            body = json.dumps(line["body"], separators=(",", ":")).encode()
            status = post(
                base + endpoint,
                body,
                {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                    "X-Agent-Id": agent_id,
                },
            )
            if not 200 <= status < 300:
                raise ForwardError(
                    f"server answered {status or 'no response'} for {endpoint}; "
                    f"stopped at byte {offset}, will resume there"
                )
            offset += len(raw)
            offset_file.write_text(str(offset))
            sent += 1
    return {"sent": sent, "offset": offset}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Forward an edr-agent spool file to the server.")
    parser.add_argument("--spool", type=Path, required=True)
    parser.add_argument("--server-url", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument(
        "--token-env",
        default="EDR_AGENT_TOKEN",
        help="environment variable holding the enrollment token",
    )
    parser.add_argument("--ca-file", help="PEM bundle to trust instead of the system store")
    args = parser.parse_args(argv)
    setup_logging("INFO")
    token = os.environ.get(args.token_env)
    if not token:
        print(f"forwarder: environment variable {args.token_env} is not set", file=sys.stderr)
        return 2
    try:
        result = forward(
            args.spool, args.server_url, args.agent_id, token, urllib_poster(args.ca_file)
        )
    except (ForwardError, OSError, ValueError) as exc:
        print(f"forwarder: {exc}", file=sys.stderr)
        return 1
    print(f"forwarded {result['sent']} batch(es)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
