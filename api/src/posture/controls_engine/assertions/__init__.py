"""Assertion modules; importing this package populates `controls_engine.model.REGISTRY`."""

from ..model import REGISTRY, Assertion
from . import certmanager, gateway, keycloak, kubernetes, observability, pack, registry  # noqa: F401


def all_assertions() -> list[Assertion]:
    return sorted(REGISTRY.values(), key=lambda a: a.id)


def get_assertion(assertion_id: str) -> Assertion | None:
    return REGISTRY.get(assertion_id)
