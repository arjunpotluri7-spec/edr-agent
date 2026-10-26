"""``python -m edr_server`` commands: serve, migrate, hash-token."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from edr_server.security import token_hash
from edr_server.settings import Settings, SettingsError

SERVER_DIR = Path(__file__).resolve().parents[2]


def _alembic_config(settings: Settings):
    from alembic.config import Config

    cfg = Config(str(SERVER_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(SERVER_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
    cfg.attributes["edr_configured"] = True
    return cfg


def migrate(settings: Settings) -> None:
    from alembic import command

    command.upgrade(_alembic_config(settings), "head")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m edr_server")
    sub = parser.add_subparsers(dest="cmd", required=True)
    serve = sub.add_parser("serve", help="run the API with uvicorn")
    serve.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--no-migrate", action="store_true", help="skip alembic upgrade head")
    sub.add_parser("migrate", help="apply database migrations")
    sub.add_parser(
        "hash-token", help="read a token on stdin and print its SHA-256 for EDR_AGENT_TOKEN_HASHES"
    )
    args = parser.parse_args(argv)

    if args.cmd == "hash-token":
        token = getpass.getpass("token: ") if sys.stdin.isatty() else sys.stdin.readline()
        token = token.strip()
        if len(token) < 24:
            print("hash-token: use a random token of at least 24 characters", file=sys.stderr)
            return 2
        print(token_hash(token))
        return 0
    try:
        settings = Settings.from_env()
    except SettingsError as exc:
        print(f"edr_server: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "migrate":
        migrate(settings)
        return 0
    import uvicorn

    from edr_server.app import create_app
    from edr_server.logsetup import setup_logging

    setup_logging(settings.log_level, settings.log_format)
    if not args.no_migrate:
        migrate(settings)
    uvicorn.run(
        create_app(settings),
        host=args.host,
        port=args.port,
        proxy_headers=False,
        server_header=False,
        log_level=settings.log_level.lower(),
    )
    return 0
