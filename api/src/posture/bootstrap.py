"""`python -m posture.bootstrap ensure-secret ...`: create a Secret with random values once.

Used by the chart's pre-install/pre-upgrade hook Jobs (Argo CD: PreSync) instead of
Helm `lookup`, which returns nothing under `helm template` / Argo CD and made every
render rotate the database password (architecture review B1). The Secret is created
only when it is absent; an existing Secret only gains keys (and annotations) it lacks,
values are never rewritten. The hook's Role allows `create` on Secrets in the release namespace and
`get`/`patch` on exactly the names it manages.
"""

from __future__ import annotations

import argparse
import base64
import os
import secrets
import string
import sys
from typing import Any

ALPHABET = string.ascii_letters + string.digits  # URL-safe: passwords are spliced into DATABASE_URL


def random_value(length: int = 32) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def _pairs(items: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        k, _, v = item.partition("=")
        if k:
            out[k] = v
    return out


def ensure_secret(api: Any, namespace: str, name: str, keys: list[str], length: int = 32,
                  labels: dict[str, str] | None = None, annotations: dict[str, str] | None = None) -> str:
    """Returns "created", "patched" (missing keys added) or "unchanged"."""
    from kubernetes.client.exceptions import ApiException

    try:
        existing = api.read_namespaced_secret(name, namespace)
    except ApiException as e:
        if e.status != 404:
            raise
        existing = None
    if existing is None:
        body = {
            "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": name, "namespace": namespace, "labels": labels or {},
                         "annotations": annotations or {}},
            "data": {k: base64.b64encode(random_value(length).encode()).decode() for k in keys},
        }
        try:
            api.create_namespaced_secret(namespace, body)
            return "created"
        except ApiException as e:
            if e.status != 409:  # created concurrently: fall through to the key check
                raise
            existing = api.read_namespaced_secret(name, namespace)
    missing = [k for k in keys if k not in (existing.data or {})]
    have = dict(getattr(getattr(existing, "metadata", None), "annotations", None) or {})
    # e.g. a Secret created by an older chart via Helm `lookup`: make sure it survives
    # Argo CD pruning / helm uninstall now that the chart no longer renders it
    add_ann = {k: v for k, v in (annotations or {}).items() if have.get(k) != v}
    if not missing and not add_ann:
        return "unchanged"
    patch: dict[str, Any] = {}
    if missing:
        patch["data"] = {k: base64.b64encode(random_value(length).encode()).decode() for k in missing}
    if add_ann:
        patch["metadata"] = {"annotations": add_ann}
    api.patch_namespaced_secret(name, namespace, patch)
    return "patched"


def _core_api() -> Any:
    from kubernetes import client, config

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m posture.bootstrap")
    sub = parser.add_subparsers(dest="cmd", required=True)
    es = sub.add_parser("ensure-secret", help="create a Secret with random values if it does not exist")
    es.add_argument("--namespace", default=os.environ.get("POD_NAMESPACE", "default"))
    es.add_argument("--name", required=True)
    es.add_argument("--key", action="append", required=True, help="data key to fill (repeatable)")
    es.add_argument("--length", type=int, default=32)
    es.add_argument("--label", action="append", help="k=v (repeatable)")
    es.add_argument("--annotation", action="append", help="k=v (repeatable)")
    args = parser.parse_args(argv)
    result = ensure_secret(_core_api(), args.namespace, args.name, args.key, args.length,
                           _pairs(args.label), _pairs(args.annotation))
    print(f"secret {args.namespace}/{args.name}: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
