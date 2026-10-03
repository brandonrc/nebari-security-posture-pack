"""In-memory registry / cosign fakes for the provenance tests (no network)."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from posture.provenance.registry import MT_DOCKER_MANIFEST, MT_OCI_INDEX, MT_OCI_MANIFEST, Manifest, RegistryError


def digest_of(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


class FakeRegistry:
    def __init__(self):
        self.manifests: dict[tuple[str, str, str], Manifest] = {}
        self.blobs: dict[tuple[str, str, str], bytes] = {}
        self.tags: dict[tuple[str, str], list[str]] = {}
        self.referrers_api: dict[tuple[str, str, str], list[dict]] = {}
        self.fail: set[str] = set()  # registries that raise RegistryError
        self.calls: list[tuple[str, ...]] = []
        self.closed = False

    # -- builders
    def put(self, registry: str, repo: str, reference: str, body: dict, media_type: str | None = None) -> str:
        d = digest_of(body)
        mt = media_type or body.get("mediaType") or MT_OCI_MANIFEST
        m = Manifest(mt, d, body)
        self.manifests[(registry, repo, reference)] = m
        self.manifests[(registry, repo, d)] = m
        return d

    def image_index(self, registry: str, repo: str, tag: str, attestation_predicates: list[str] | None = None) -> str:
        manifests = [{"mediaType": MT_OCI_MANIFEST, "digest": "sha256:" + "a" * 64,
                      "platform": {"os": "linux", "architecture": "amd64"}}]
        if attestation_predicates is not None:
            att = {"mediaType": MT_OCI_MANIFEST, "layers": [
                {"mediaType": "application/vnd.in-toto+json", "digest": "sha256:" + str(i) * 64,
                 "annotations": {"in-toto.io/predicate-type": p}} for i, p in enumerate(attestation_predicates)]}
            att_digest = self.put(registry, repo, "att-" + tag, att)
            manifests.append({"mediaType": MT_OCI_MANIFEST, "digest": att_digest,
                              "platform": {"os": "unknown", "architecture": "unknown"},
                              "annotations": {"vnd.docker.reference.type": "attestation-manifest",
                                              "vnd.docker.reference.digest": "sha256:" + "a" * 64}})
        return self.put(registry, repo, tag, {"schemaVersion": 2, "mediaType": MT_OCI_INDEX, "manifests": manifests},
                        MT_OCI_INDEX)

    def single(self, registry: str, repo: str, tag: str) -> str:
        return self.put(registry, repo, tag, {"schemaVersion": 2, "mediaType": MT_DOCKER_MANIFEST,
                                              "config": {"digest": "sha256:" + "c" * 64}, "layers": []},
                        MT_DOCKER_MANIFEST)

    def cosign_sig(self, registry: str, repo: str, digest: str) -> None:
        self.put(registry, repo, digest.replace(":", "-") + ".sig", {"schemaVersion": 2, "layers": [
            {"mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": "sha256:" + "5" * 64,
             "annotations": {"dev.cosignproject.cosign/signature": "MEUC..."}}]})

    def cosign_att(self, registry: str, repo: str, digest: str, predicate_type: str, annotate: bool = True,
                   predicate: dict | None = None) -> None:
        stmt = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": predicate_type,
                "predicate": predicate or {}}
        env = {"payloadType": "application/vnd.in-toto+json",
               "payload": base64.b64encode(json.dumps(stmt).encode()).decode(), "signatures": []}
        blob = json.dumps(env).encode()
        bd = "sha256:" + hashlib.sha256(blob).hexdigest()
        self.blobs[(registry, repo, bd)] = blob
        ann = {"predicateType": predicate_type} if annotate else {}
        self.put(registry, repo, digest.replace(":", "-") + ".att", {"schemaVersion": 2, "layers": [
            {"mediaType": "application/vnd.dsse.envelope.v1+json", "digest": bd, "annotations": ann}]})

    def bundle_referrer(self, registry: str, repo: str, digest: str, content: str, predicate_type: str = "",
                        via: str = "api") -> None:
        ann = {"dev.sigstore.bundle.content": content}
        if predicate_type:
            ann["dev.sigstore.bundle.predicateType"] = predicate_type
        desc = {"mediaType": MT_OCI_MANIFEST, "digest": "sha256:" + "b" * 64,
                "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json", "annotations": ann}
        if via == "api":
            self.referrers_api.setdefault((registry, repo, digest), []).append(desc)
        else:
            key = (registry, repo, digest.replace(":", "-"))
            cur = self.manifests.get(key)
            manifests = (cur.body.get("manifests") if cur else []) + [desc]
            self.manifests[key] = Manifest(MT_OCI_INDEX, None, {"schemaVersion": 2, "manifests": manifests})

    # -- Registry protocol
    def _check(self, registry: str) -> None:
        if registry in self.fail:
            raise RegistryError(f"{registry}: connection refused")

    async def get_manifest(self, registry, repository, reference):
        self.calls.append(("manifest", registry, repository, reference))
        self._check(registry)
        return self.manifests.get((registry, repository, reference))

    async def manifest_exists(self, registry, repository, reference):
        self.calls.append(("head", registry, repository, reference))
        self._check(registry)
        return (registry, repository, reference) in self.manifests

    async def get_blob(self, registry, repository, digest, max_bytes=2 * 1024 * 1024):
        self._check(registry)
        return self.blobs.get((registry, repository, digest))

    async def list_tags(self, registry, repository):
        self.calls.append(("tags", registry, repository))
        self._check(registry)
        return list(self.tags.get((registry, repository), []))

    async def referrers(self, registry, repository, digest):
        self._check(registry)
        return self.referrers_api.get((registry, repository, digest))

    async def aclose(self):
        self.closed = True


class FakeCosign:
    def __init__(self, ok_refs: set[str] | None = None):
        self.ok_refs = ok_refs or set()
        self.calls: list[str] = []

    async def verify(self, image_ref: str, insecure: bool = False):
        self.calls.append(image_ref)
        if any(image_ref.startswith(r) or image_ref == r for r in self.ok_refs):
            return True, ""
        return False, "verification failed: no matching signatures"
