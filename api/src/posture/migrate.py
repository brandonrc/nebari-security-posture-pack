"""`python -m posture.migrate` -> alembic upgrade head (retries while the DB starts)."""

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


if __name__ == "__main__":
    sys.exit(main())
