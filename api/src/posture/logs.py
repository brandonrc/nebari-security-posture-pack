"""Structured key=value logging on top of stdlib logging. Never log tokens."""

from __future__ import annotations

import logging
import sys
from datetime import UTC, datetime
from typing import Any

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


def _fmt_value(v: Any) -> str:
    s = str(v)
    if s == "" or any(c in s for c in ' "=\n\t'):
        s = '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
    return s


class KVFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        parts = [f"ts={ts}", f"level={record.levelname.lower()}", f"logger={record.name}",
                 f"event={_fmt_value(record.getMessage())}"]
        kv = getattr(record, "kv", None) or {}
        for key, value in kv.items():
            parts.append(f"{key}={_fmt_value(value)}")
        for key, value in record.__dict__.items():
            if key not in _RESERVED and key not in ("kv", "color_message") and not key.startswith("_"):
                parts.append(f"{key}={_fmt_value(value)}")
        if record.exc_info:
            parts.append(f"exc={_fmt_value(self.formatException(record.exc_info))}")
        return " ".join(parts)


class KVLogger:
    """`log.info("scan.started", scan_id=1)` -> `event=scan.started scan_id=1`."""

    def __init__(self, name: str):
        self._log = logging.getLogger(name)

    def _emit(self, level: int, event: str, exc_info: Any = None, **kv: Any) -> None:
        if self._log.isEnabledFor(level):
            self._log.log(level, event, extra={"kv": kv}, exc_info=exc_info)

    def debug(self, event: str, **kv: Any) -> None:
        self._emit(logging.DEBUG, event, **kv)

    def info(self, event: str, **kv: Any) -> None:
        self._emit(logging.INFO, event, **kv)

    def warning(self, event: str, **kv: Any) -> None:
        self._emit(logging.WARNING, event, **kv)

    def error(self, event: str, exc_info: Any = None, **kv: Any) -> None:
        self._emit(logging.ERROR, event, exc_info=exc_info, **kv)

    def exception(self, event: str, **kv: Any) -> None:
        self._emit(logging.ERROR, event, exc_info=True, **kv)


def get_logger(name: str) -> KVLogger:
    return KVLogger(name)


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(KVFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    for noisy in ("uvicorn.access", "httpx", "httpcore", "kubernetes", "urllib3", "apscheduler"):
        logging.getLogger(noisy).setLevel(max(logging.WARNING, root.level))
    for name in ("uvicorn", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers[:] = []
        lg.propagate = True
