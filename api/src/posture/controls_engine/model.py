"""Assertion model: `Result`, `Assertion` and the `@assertion` registry decorator."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .context import EngineContext

PASS, FAIL, UNKNOWN, NA = "pass", "fail", "unknown", "not-applicable"
ASSERTION_STATUSES = (PASS, FAIL, UNKNOWN, NA)
SEVERITIES = ("critical", "high", "medium", "low")


@dataclass
class Result:
    status: str
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in ASSERTION_STATUSES:
            raise ValueError(f"invalid assertion status {self.status!r}")


def passed(detail: str, **evidence: Any) -> Result:
    return Result(PASS, detail, evidence)


def failed(detail: str, **evidence: Any) -> Result:
    return Result(FAIL, detail, evidence)


def unknown(detail: str, **evidence: Any) -> Result:
    return Result(UNKNOWN, detail, evidence)


def not_applicable(detail: str, **evidence: Any) -> Result:
    return Result(NA, detail, evidence)


Evaluate = Callable[["EngineContext"], Awaitable[Result]]


@dataclass(frozen=True)
class Assertion:
    """One live check. `controls` use the 800-53 label form (`AC-6(10)`)."""

    id: str
    title: str
    controls: tuple[str, ...]
    component: str
    severity: str
    evaluate: Evaluate = field(compare=False, repr=False)
    description: str = ""
    # SP 800-53A assessment objectives this assertion produces evidence for (`ac-7_obj.a`; a parent
    # such as `si-2_obj.c` covers its leaves). Objective coverage drives the control status (M2).
    objectives: tuple[str, ...] = ()

    def meta(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "controls": list(self.controls), "component": self.component,
                "severity": self.severity, "description": self.description, "objectives": list(self.objectives)}


REGISTRY: dict[str, Assertion] = {}


def assertion(*, id: str, title: str, controls: list[str], component: str, severity: str = "medium",  # noqa: A002
              description: str = "", objectives: list[str] | None = None) -> Callable[[Evaluate], Assertion]:
    """Register `async def fn(ctx) -> Result` as an assertion."""
    if severity not in SEVERITIES:
        raise ValueError(f"invalid severity {severity!r}")

    def deco(fn: Evaluate) -> Assertion:
        if id in REGISTRY:
            raise ValueError(f"duplicate assertion id {id!r}")
        a = Assertion(id=id, title=title, controls=tuple(controls), component=component, severity=severity,
                      evaluate=fn, description=description or (fn.__doc__ or "").strip(),
                      objectives=tuple(o.strip().lower() for o in objectives or ()))
        REGISTRY[id] = a
        return a

    return deco
