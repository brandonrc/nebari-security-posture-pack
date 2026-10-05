"""Risk acceptances (`controlsEngine.exceptions[]`): AO-approved, workload-scoped exceptions to
posture checks and control assertions (grace 2026-10-05: the scap-worker must run as root with six
capabilities, and the only lever before this was exempting its whole namespace).

Semantics (one place, used by the posture checks, the controls engine and the reports):

* An exception names one workload (`kind`, `namespace`, `name`; `name` may be an fnmatch glob,
  `kind` may be `*`) and the posture `checks` and/or controls-engine `assertions` it covers.
* A covered failing result is **not** turned into a pass: its status becomes `accepted-risk`
  (`ACCEPTED_RISK`). The finding stays visible with the reason, approver and expiry appended to its
  detail.
* `accepted-risk` results carry no score penalty (posture weight 0, not counted as failed), are not
  failing scan evidence for the controls engine, and are listed as "Risk acceptance" rows in the
  POA&M / SAR and in the CRM.
* For the controls engine an assertion whose only failures are accepted resolves to
  `accepted-risk` (never `pass`): the objectives it evidences are `risk-accepted`, so the mapped
  controls can be at most `partial`, never `passing`.
* `expiresAt` (inclusive, UTC date) ends the acceptance: from the next day the result is `fail`
  again (detail notes the lapsed acceptance). `reviewBy` does not expire anything; a past
  `reviewBy` is flagged `reviewOverdue` in the reports.
* Sources: `settings` (PUT /settings, editable) and `values` (chart `controlsEngine.exceptions`,
  env CONTROLS_EXCEPTIONS, read-only: re-applied on every settings load, never stored).
"""

from __future__ import annotations

import fnmatch
import json
from collections.abc import Iterable
from datetime import UTC, date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.alias_generators import to_camel

ACCEPTED_RISK = "accepted-risk"


def today_utc() -> date:
    return datetime.now(UTC).date()


class RiskException(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")

    kind: str
    namespace: str
    name: str
    checks: list[str] = Field(default_factory=list)  # posture check ids (posture_checks.CHECKS)
    assertions: list[str] = Field(default_factory=list)  # controls-engine assertion ids
    reason: str
    approved_by: str
    expires_at: date | None = None  # last day the acceptance applies; None = no expiry
    review_by: date | None = None  # next review date (informational)
    ticket: str = ""
    source: str = "settings"  # settings | values (chart; read-only)

    @field_validator("kind", "namespace", "name", "reason", "approved_by")
    @classmethod
    def _required(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("kind, namespace, name, reason and approvedBy are required")
        return v

    @field_validator("checks", "assertions")
    @classmethod
    def _ids(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(s.strip() for s in v if s and s.strip()))

    @field_validator("expires_at", "review_by", mode="before")
    @classmethod
    def _date(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return None
            return date.fromisoformat(v[:10])
        if isinstance(v, datetime):
            return v.date()
        return v

    @model_validator(mode="after")
    def _scope(self) -> RiskException:
        if not self.checks and not self.assertions:
            raise ValueError("an exception must list at least one of checks / assertions")
        return self

    @property
    def key(self) -> str:
        return f"{self.namespace}/{self.kind}/{self.name}"

    def active(self, today: date | None = None) -> bool:
        return self.expires_at is None or (today or today_utc()) <= self.expires_at

    def review_overdue(self, today: date | None = None) -> bool:
        return self.review_by is not None and (today or today_utc()) > self.review_by

    def matches(self, kind: str, namespace: str, name: str) -> bool:
        return ((self.kind == "*" or self.kind.lower() == (kind or "").lower()) and self.namespace == namespace
                and fnmatch.fnmatchcase(name or "", self.name))

    def covers(self, kind: str, namespace: str, name: str, *, check: str | None = None,
               assertion: str | None = None) -> bool:
        if not self.matches(kind, namespace, name):
            return False
        return (check is not None and check in self.checks) or (assertion is not None and assertion in self.assertions)

    def terms(self) -> str:
        parts = [f"approved by {self.approved_by}"]
        parts.append(f"expires {self.expires_at.isoformat()}" if self.expires_at else "no expiry")
        if self.review_by:
            parts.append(f"review by {self.review_by.isoformat()}")
        if self.ticket:
            parts.append(f"ticket {self.ticket}")
        return "; ".join(parts)

    def label(self) -> str:
        return f"accepted risk: {self.reason} ({self.terms()})"

    def as_dict(self, today: date | None = None) -> dict[str, Any]:
        d = self.model_dump(by_alias=True, mode="json")
        d["key"] = self.key
        d["active"] = self.active(today)
        d["reviewOverdue"] = self.review_overdue(today)
        return d


def coerce(items: Iterable[Any] | None) -> list[RiskException]:
    out = []
    for x in items or []:
        out.append(x if isinstance(x, RiskException) else RiskException.model_validate(x))
    return out


def find(exceptions: Iterable[Any] | None, kind: str, namespace: str, name: str, *, check: str | None = None,
         assertion: str | None = None, today: date | None = None) -> tuple[RiskException | None, RiskException | None]:
    """(active exception covering the result, expired one) - at most one of each, first match wins."""
    active = expired = None
    for e in coerce(exceptions):
        if not e.covers(kind, namespace, name, check=check, assertion=assertion):
            continue
        if e.active(today):
            return e, None
        expired = expired or e
    return active, expired


def parse_env(value: Any) -> list[dict[str, Any]]:
    """CONTROLS_EXCEPTIONS: a JSON list (chart `controlsEngine.exceptions`). Invalid entries raise."""
    if value in (None, ""):
        return []
    data = json.loads(value) if isinstance(value, str) else value
    if not isinstance(data, list):
        raise ValueError("CONTROLS_EXCEPTIONS must be a JSON list")
    return [{**RiskException.model_validate(d).model_dump(by_alias=True, mode="json"), "source": "values"}
            for d in data]
