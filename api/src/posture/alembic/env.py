"""Alembic environment (async engine; URL from DATABASE_URL)."""

from __future__ import annotations

import asyncio

from alembic import context
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from posture.config import Settings
# Every module that declares tables on Base.metadata must be imported here, or
# autogenerate / `alembic check` silently ignores its tables (tests/test_migrations.py).
import posture.controls_engine.models  # noqa: F401  (DESIGN §13 tables)
import posture.provenance.models  # noqa: F401  (DESIGN §12 tables)
import posture.scap.models  # noqa: F401  (DESIGN §14 tables)
from posture.db.models import Base

target_metadata = Base.metadata


def _url() -> str:
    url = context.config.get_main_option("sqlalchemy.url")
    return Settings(database_url=url).database_url if url else Settings().database_url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True,
                      dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def _do_run(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


# Session-level advisory lock held for the whole upgrade: the pre-upgrade hook Job and the
# api init container (and api replicas) may run `alembic upgrade head` concurrently.
MIGRATION_LOCK_KEY = 724_100


async def run_migrations_online() -> None:
    engine = create_async_engine(_url())
    async with engine.connect() as conn:
        await conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": MIGRATION_LOCK_KEY})
        await conn.commit()
        try:
            await conn.run_sync(_do_run)
            await conn.commit()
        finally:
            await conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": MIGRATION_LOCK_KEY})
            await conn.commit()
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
