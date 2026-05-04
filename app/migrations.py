from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from app.database import Base
import app.db_models  # noqa: F401 - register SQLAlchemy models before create_all


LATEST_REVISION = "20260504_01"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_migrations_table(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    revision VARCHAR(64) PRIMARY KEY,
                    applied_at TIMESTAMP NOT NULL
                )
                """
            )
        )


def _revision_applied(engine: Engine, revision: str) -> bool:
    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT revision FROM schema_migrations WHERE revision = :revision"),
            {"revision": revision},
        ).first()
    return row is not None


def _mark_revision(engine: Engine, revision: str) -> None:
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO schema_migrations (revision, applied_at) VALUES (:revision, :applied_at)"),
            {"revision": revision, "applied_at": _utc_now()},
        )


def _initial_schema(engine: Engine) -> None:
    Base.metadata.create_all(bind=engine)


def _api_key_role_upgrade(engine: Engine) -> None:
    inspector = inspect(engine)
    if "api_keys" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("api_keys")}
    statements: list[str] = []
    if "role" not in columns:
        statements.append("ALTER TABLE api_keys ADD COLUMN role VARCHAR(32) NOT NULL DEFAULT 'admin'")
    if "revoked_at" not in columns:
        statements.append("ALTER TABLE api_keys ADD COLUMN revoked_at TIMESTAMP NULL")
    if "last_used_at" not in columns:
        statements.append("ALTER TABLE api_keys ADD COLUMN last_used_at TIMESTAMP NULL")

    if not statements:
        return

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _sso_and_fga_upgrade(engine: Engine) -> None:
    Base.metadata.create_all(bind=engine)


def _blueprint_alignment_upgrade(engine: Engine) -> None:
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    if "agent_records" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("agent_records")}
        if "blueprint_id" not in columns:
            with engine.begin() as connection:
                connection.execute(text("ALTER TABLE agent_records ADD COLUMN blueprint_id VARCHAR(255) NULL"))


def migrate_database(engine: Engine) -> str:
    revisions: list[tuple[str, Callable[[Engine], None]]] = [
        ("20260427_01", _initial_schema),
        ("20260429_01", _api_key_role_upgrade),
        ("20260429_02", _sso_and_fga_upgrade),

        ("20260504_01", _sso_and_fga_upgrade),

    ]
    _ensure_migrations_table(engine)
    for revision, revision_fn in revisions:
        if _revision_applied(engine, revision):
            continue
        revision_fn(engine)
        _mark_revision(engine, revision)
    return LATEST_REVISION
