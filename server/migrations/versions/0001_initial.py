"""Initial schema: hosts, events, incidents.

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
BIG_ID = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "hosts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
    )
    op.create_table(
        "events",
        sa.Column("seq", BIG_ID, primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(200), nullable=False, unique=True),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("ts_ms", sa.BigInteger(), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("pid", sa.BigInteger(), nullable=False),
        sa.Column("image", sa.Text(), nullable=False),
        sa.Column("data", JSON, nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_events_host_ts", "events", ["host", "ts_ms", "seq"])
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=True),
        sa.Column("agent_version", sa.Integer(), nullable=False),
        sa.Column("agent_score", sa.Integer(), nullable=True),
        sa.Column("agent_detail", JSON, nullable=True),
        sa.Column("server_score", sa.Integer(), nullable=True),
        sa.Column("server_detail", JSON, nullable=True),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(16), nullable=False),
        sa.Column("first_seen", sa.String(32), nullable=False),
        sa.Column("last_seen", sa.String(32), nullable=False),
        sa.Column("root_image", sa.Text(), nullable=False),
        sa.Column("root_pid", sa.BigInteger(), nullable=False),
        sa.Column("signal_count", sa.Integer(), nullable=False),
        sa.Column("attack", JSON, nullable=False),
        sa.Column("score_mismatch", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incidents_score", "incidents", ["score"])
    op.create_index("ix_incidents_host", "incidents", ["host"])


def downgrade() -> None:
    op.drop_table("incidents")
    op.drop_table("events")
    op.drop_table("hosts")
