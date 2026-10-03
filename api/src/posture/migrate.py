"""`python -m posture.migrate` -> alembic upgrade head (retries while the DB starts).

Runs from the chart's pre-upgrade hook Job (`--if-reachable`) and from the api init
container. alembic/env.py serialises concurrent runs with pg_advisory_lock.

`--if-reachable SECONDS`: when the database cannot be reached within SECONDS, exit 0
without migrating. The hook Job uses it because Argo CD maps pre-install AND pre-upgrade
to PreSync, which also runs on a first sync before the bundled Postgres exists; the api
init container (which waits for the database) migrates in that case.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from alembic import command
from alembic.config import Config

from .config import get_settings
from .logs import get_logger, setup_logging

log = get_logger("posture.migrate")


def alembic_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "alembic"))
    cfg.set_main_option("sqlalchemy.url", get_settings().database_url.replace("%", "%%"))
    return cfg


def main(retries: int = 30, delay: float = 2.0) -> int:
    setup_logging(get_settings().log_level)
    for attempt in range(1, retries + 1):
        try:
            command.upgrade(alembic_config(), "head")
            log.info("migrate.done")
            return 0
        except Exception as e:  # noqa: BLE001
            if attempt == retries:
                log.error("migrate.failed", error=str(e), exc_info=True)
                return 1
            log.warning("migrate.retry", attempt=attempt, error=str(e)[:300])
            time.sleep(delay)
    return 1


def reachable(timeout: float) -> bool:
    import asyncio

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    async def probe() -> bool:
        deadline = time.monotonic() + timeout
        while True:
            eng = create_async_engine(get_settings().database_url, connect_args={"timeout": 5})
            try:
                async with eng.connect() as conn:
                    await conn.execute(text("SELECT 1"))
                return True
            except Exception as e:  # noqa: BLE001
                if time.monotonic() >= deadline:
                    log.warning("migrate.db_unreachable", error=str(e)[:300])
                    return False
                await asyncio.sleep(3)
            finally:
                await eng.dispose()

    return asyncio.run(probe())


def cli(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m posture.migrate")
    parser.add_argument("--if-reachable", type=float, default=None, metavar="SECONDS",
                        help="skip (exit 0) when the database is unreachable for SECONDS")
    args = parser.parse_args(argv)
    if args.if_reachable is not None:
        setup_logging(get_settings().log_level)
        if not reachable(args.if_reachable):
            log.info("migrate.skipped", reason="database unreachable; the api init container migrates")
            return 0
    return main()


if __name__ == "__main__":
    sys.exit(cli())
