import os
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
# The worker runs the control evidence engine (DESIGN §13) after each scan; keep the shared harness
# hermetic (no live cluster / Keycloak). tests/controls_engine enable it with fake clients.
os.environ.setdefault("CONTROLS_ENGINE_ENABLED", "false")


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


def make_container(**kw):
    from posture.inventory_model import ContainerRecord

    base = dict(namespace="app", pod="web-abc", container="web", container_type="container",
                image="ghcr.io/org/web:1.0", image_id=None, running=True, pod_phase="Running",
                workload_kind="Deployment", workload_name="web", pod_labels={"app": "web"},
                security={"container": {}, "pod": {}})
    base.update(kw)
    return ContainerRecord(**base)


@pytest.fixture
def container_factory():
    return make_container


def pytest_collection_modifyitems(config, items):
    if os.environ.get("TEST_DATABASE_URL"):
        return
    skip = pytest.mark.skip(reason="TEST_DATABASE_URL not set (Postgres integration tests)")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)
