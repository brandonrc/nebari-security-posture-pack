"""Ported from provenance-collector-pack internal/verify/*_test.go + registry-walk tests on a fake."""

import pytest

from posture.images import ImageRef
from posture.provenance.checks import (
    CosignCli,
    CosignConfig,
    SignatureInfo,
    collect_attestations,
    detect_from_content,
    detect_sbom_format,
    is_slsa_predicate,
    predicate_types,
    provenance_info,
    sbom_format_from_predicate,
    sbom_info,
    signature_existence,
    verify_signature,
)

from .fakes import FakeCosign, FakeRegistry

# ---------------------------------------------------------------- sbom_test.go
def test_detect_sbom_format_in_toto_spdx():
    p = '{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://spdx.dev/Document", "predicate": {"spdxVersion": "SPDX-2.3"}}'
    assert detect_sbom_format(p.encode()) == "spdx"


def test_detect_sbom_format_in_toto_cyclonedx():
    p = '{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://cyclonedx.org/bom/v1.4", "predicate": {"bomFormat": "CycloneDX"}}'
    assert detect_sbom_format(p) == "cyclonedx"


def test_detect_sbom_format_unknown_predicate_with_spdx_content():
    p = '{"_type": "x", "predicateType": "https://example.com/custom", "predicate": {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}}'
    assert detect_sbom_format(p) == "spdx"


@pytest.mark.parametrize("payload,want", [
    ('{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}', "spdx"),
    ('{"bomFormat": "CycloneDX", "specVersion": "1.4"}', "cyclonedx"),
    ("{}", ""),
    ("not json but has SPDXRef- in it", "spdx"),
    ("just some random text", ""),
])
def test_detect_sbom_format_raw(payload, want):
    assert detect_sbom_format(payload) == want


@pytest.mark.parametrize("pt,want", [
    ("https://spdx.dev/Document", "spdx"), ("https://spdx.dev/Document/v2.3", "spdx"),
    ("https://cyclonedx.org/bom", "cyclonedx"), ("https://cyclonedx.org/bom/v1.5", "cyclonedx"),
    ("https://slsa.dev/provenance/v1", ""), ("https://in-toto.io/provenance/v1", ""), ("", ""), ("random", ""),
])
def test_sbom_format_from_predicate(pt, want):
    assert sbom_format_from_predicate(pt) == want


@pytest.mark.parametrize("text,want", [
    ('"documentNamespace": "https://spdx.dev/Document/test"', "spdx"),
    ('"SPDXID": "SPDXRef-Package"', "spdx"),
    ('"bomFormat": "CycloneDX"', "cyclonedx"),
    ('"specVersion": "cyclonedx/1.4"', "cyclonedx"),
    ('{"name": "test"}', ""),
])
def test_detect_from_content(text, want):
    assert detect_from_content(text) == want


# ---------------------------------------------------------------- provenance_test.go
@pytest.mark.parametrize("pt,want", [
    ("https://slsa.dev/provenance/v1", True), ("https://slsa.dev/provenance/v0.2", True),
    ("https://in-toto.io/provenance/v1", True), ("https://in-toto.io/provenance/v0.1", True),
    ("https://spdx.dev/Document", False), ("https://cyclonedx.org/bom", False),
    ("https://slsa.dev/verification_summary/v1", False), ("", False), ("random string", False),
])
def test_is_slsa_predicate(pt, want):
    assert is_slsa_predicate(pt) is want


# ---------------------------------------------------------------- referrers_test.go
@pytest.mark.parametrize("ann,want", [
    ({"dev.sigstore.bundle.predicateType": "https://slsa.dev/provenance/v1"}, ["https://slsa.dev/provenance/v1"]),
    ({"in-toto.io/predicate-type": "https://spdx.dev/Document"}, ["https://spdx.dev/Document"]),
    ({"org.example.predicate": "https://cyclonedx.org/bom"}, ["https://cyclonedx.org/bom"]),
    (None, []),
])
def test_predicate_types(ann, want):
    got = predicate_types({"annotations": ann} if ann is not None else {})
    assert all(w in got for w in want) and (want or not got)


def test_predicate_types_dedicated_annotations_first():
    got = predicate_types({"annotations": {"z": "other", "in-toto.io/predicate-type": "B",
                                           "dev.sigstore.bundle.predicateType": "A"}})
    assert got[:2] == ["A", "B"] and "other" in got


# ---------------------------------------------------------------- registry walk (fake)
REG, REPO = "ghcr.io", "org/app"


async def _collect(reg, digest=None, tag="1.0.0"):
    return await collect_attestations(reg, ImageRef(REG, REPO, tag, digest))


async def test_invalid_or_unreachable_ref_has_nothing_and_no_exception():
    reg = FakeRegistry()
    reg.fail.add(REG)
    a = await _collect(reg)
    assert a.error and sbom_info(a).has_sbom is False and provenance_info(a).has_provenance is False
    assert signature_existence(a).as_json() == {"signed": False, "verified": False, "error": a.error}


async def test_missing_manifest():
    a = await _collect(FakeRegistry())
    assert "not found" in a.error and not signature_existence(a).signed


async def test_buildkit_index_attestation_sbom_and_provenance():
    """buildkit_attest_test.go: docker/build-push-action layout."""
    reg = FakeRegistry()
    d = reg.image_index(REG, REPO, "1.0.0", ["https://spdx.dev/Document", "https://slsa.dev/provenance/v0.2"])
    a = await _collect(reg, d)
    assert a.index_predicates == ["https://spdx.dev/Document", "https://slsa.dev/provenance/v0.2"]
    assert sbom_info(a).as_json() == {"hasSBOM": True, "format": "spdx"} and sbom_info(a).source == "index-attestation"
    assert provenance_info(a).as_json() == {"hasProvenance": True, "predicateType": "https://slsa.dev/provenance/v0.2"}
    assert signature_existence(a).as_json() == {"signed": False, "verified": False}


async def test_buildkit_index_without_sbom():
    reg = FakeRegistry()
    d = reg.image_index(REG, REPO, "1.0.0", ["https://slsa.dev/provenance/v1"])
    a = await _collect(reg, d)
    assert sbom_info(a).has_sbom is False and provenance_info(a).has_provenance is True


async def test_legacy_cosign_sig_and_att_tags():
    reg = FakeRegistry()
    d = reg.single(REG, REPO, "1.0.0")
    reg.cosign_sig(REG, REPO, d)
    reg.cosign_att(REG, REPO, d, "https://cyclonedx.org/bom/v1.5")
    a = await _collect(reg, d)
    assert a.sig_tag and signature_existence(a).as_json() == {"signed": True, "verified": False}
    assert sbom_info(a).as_json() == {"hasSBOM": True, "format": "cyclonedx"}
    assert provenance_info(a).has_provenance is False


async def test_cosign_att_without_annotation_decodes_dsse_payload():
    reg = FakeRegistry()
    d = reg.single(REG, REPO, "1.0.0")
    reg.cosign_att(REG, REPO, d, "https://slsa.dev/provenance/v1", annotate=False)
    a = await _collect(reg, d)
    assert a.att_payloads and provenance_info(a).as_json() == {"hasProvenance": True,
                                                              "predicateType": "https://slsa.dev/provenance/v1"}


async def test_sigstore_bundles_via_referrers_api_and_fallback_tag():
    for via in ("api", "tag"):
        reg = FakeRegistry()
        d = reg.single(REG, REPO, "1.0.0")
        reg.bundle_referrer(REG, REPO, d, "message-signature", via=via)
        reg.bundle_referrer(REG, REPO, d, "dsse-envelope", "https://slsa.dev/provenance/v1", via=via)
        reg.bundle_referrer(REG, REPO, d, "dsse-envelope", "https://spdx.dev/Document", via=via)
        a = await _collect(reg, d)
        assert a.referrers_source == via and len(a.referrers) == 3
        assert signature_existence(a).signed is True
        assert sbom_info(a).source == "referrers" and sbom_info(a).format == "spdx"
        assert provenance_info(a).predicate_type == "https://slsa.dev/provenance/v1"


async def test_attestation_bundle_alone_is_not_a_signature():
    reg = FakeRegistry()
    d = reg.single(REG, REPO, "1.0.0")
    reg.bundle_referrer(REG, REPO, d, "dsse-envelope", "https://slsa.dev/provenance/v1")
    assert signature_existence(await _collect(reg, d)).signed is False


async def test_cosign_attach_sbom_tag():
    reg = FakeRegistry()
    d = reg.single(REG, REPO, "1.0.0")
    reg.put(REG, REPO, d.replace(":", "-") + ".sbom", {"layers": [{"mediaType": "text/spdx+json", "digest": "x"}]})
    assert sbom_info(await _collect(reg, d)).as_json() == {"hasSBOM": True, "format": "spdx"}


async def test_tag_ref_resolves_digest():
    reg = FakeRegistry()
    d = reg.single(REG, REPO, "1.0.0")
    a = await _collect(reg, None, "1.0.0")
    assert a.digest == d


# ---------------------------------------------------------------- cosign_test.go equivalents
async def test_verify_signature_paths():
    signed = SignatureInfo(signed=True)
    assert await verify_signature(signed, None, "x") is signed  # existence only (no key)
    ok = await verify_signature(signed, FakeCosign({"ghcr.io/org/app@"}), "ghcr.io/org/app@sha256:1")
    assert ok.as_json() == {"signed": True, "verified": True}
    bad = await verify_signature(signed, FakeCosign(), "ghcr.io/org/app@sha256:1")
    assert bad.signed and not bad.verified and bad.error.startswith("verification failed")
    cos = FakeCosign({"x"})
    unsigned = await verify_signature(SignatureInfo(False), cos, "x")
    assert unsigned.signed is False and cos.calls == []  # no cosign run for unsigned images


def test_cosign_cli_argv_key_and_keyless(tmp_path):
    key = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----"
    cli = CosignCli(CosignConfig(public_key=key))
    argv = cli.argv("reg/app@sha256:1", insecure=True)
    assert argv[:4] == ["cosign", "verify", "--output", "json"] and "--insecure-ignore-tlog=true" in argv
    key_path = argv[argv.index("--key") + 1]
    assert open(key_path).read().startswith("-----BEGIN") and "--allow-http-registry" in argv
    assert CosignCli(CosignConfig(public_key="awskms:///alias/x")).argv("r")[5] == "awskms:///alias/x"
    kl = CosignCli(CosignConfig(certificate_identity_regexp="^https://github.com/org/",
                                certificate_oidc_issuer_regexp="token.actions")).argv("r")
    assert "--certificate-identity-regexp" in kl and "--key" not in kl
    assert not CosignConfig().enabled and not CosignConfig(certificate_identity_regexp="x").enabled


def test_cosign_cli_double_dash_and_unsafe_ref():
    cli = CosignCli(CosignConfig(public_key="/k.pub"))
    assert cli.argv("reg.io/app@sha256:1")[-2:] == ["--", "reg.io/app@sha256:1"]
    with pytest.raises(ValueError):
        cli.argv("--key=/etc/passwd")


async def test_cosign_cli_refuses_flag_like_ref():
    ok, err = await CosignCli(CosignConfig(public_key="/k.pub"), binary="/nonexistent").verify("-x")
    assert ok is False and "unsafe" in err


async def test_cosign_cli_missing_binary_is_verification_failure():
    cli = CosignCli(CosignConfig(public_key="/nonexistent/key.pub"), binary="/nonexistent/cosign")
    ok, err = await cli.verify("ghcr.io/org/app@sha256:1")
    assert ok is False and err.startswith("verification failed")
