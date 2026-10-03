# Proposal: merge provenance-collector-pack and nebari-security-posture-pack

Status: draft for discussion with the provenance-collector-pack maintainers.
Author: Brandon Geraci. Target repo for the PR: `nebari-dev/provenance-collector-pack`.

## Summary

Combine the two packs into one Nebari software pack that answers the full
compliance question for a cluster: *where did every running image come from*
(provenance), *what is wrong with it* (three-scanner vulnerability consensus),
*how is it run* (Kubernetes posture checks mapped to the Kubernetes STIG), and
*which 800-53 controls does the platform implement and prove* (control evidence
engine). Provenance becomes one of four evidence layers rather than a separate
product, and the existing provenance report API and Grafana integration keep
working unchanged.

See the diagrams in [ARCHITECTURE.md](../ARCHITECTURE.md).

## What each side brings

| provenance-collector-pack (Go, alpha, NIC foundational) | nebari-security-posture-pack (Python + React, experimental) |
|---|---|
| Image and Helm discovery, digest resolution | Image inventory by digest with owner resolution and NebariApp mapping |
| cosign verification, SLSA and SBOM attestation detection, update checks | Trivy + Grype + Clair consensus, 16 posture checks, scoring and grades |
| Timestamped JSON report, `/api/reports/*`, Grafana Infinity dashboard | POA&M (eMASS layout), STIG CKL/CKLB, SAR PDF, OSCAL AR/SSP/component-definition, CycloneDX VEX |
| Thin React table UI | Full admin UI built on `nebari-design` (shared Nebari header, tokens, components) |
| CronJob, PVC/ConfigMap/HTTP sinks, docs site, release workflow | Worker + Postgres + Trivy server + Clair; gateway admin gate; NIST 800-53 control evidence engine (35 live assertions) |

## Proposed end state

- **One repo, one chart, one UI.** The UI is the nebari-design one; the thin
  provenance table is retired.
- **The provenance collector survives as the provenance engine.** Rather than
  keeping two implementations, the worker image bundles the existing Go
  `provenance-collector` binary and ingests its JSON report (its schema is
  already the compatibility contract). The Python port written in the posture
  pack becomes a fallback and can be deleted once the binary path is proven.
  This keeps the maintainers' code, tests and future work alive instead of
  rewriting it.
- **API compatibility preserved.** `/api/reports`, `/api/reports/latest`,
  `/api/export`, `/api/me`, `/api/scan`, `/healthz` are served unchanged, plus an
  unauthenticated internal Service for Grafana, exactly as today.
- **Values compatibility.** The `config.*` keys (`verifySignatures`, `checkSBOM`,
  `checkProvenance`, `checkUpdates`, `updateLevel`, `skipPrerelease`, cosign key
  options) are honoured under `provenance.*`, with a documented mapping.
- **Name.** The combined pack is no longer "provenance", so the repo and chart
  are renamed. Suggested: `nebari-security-posture-pack` (chart
  `nebari-security-posture-pack`). GitHub redirects the old repo URL; the chart
  rename is a one-time breaking change announced in the release notes with a
  values migration snippet. If the maintainers prefer to keep the repo name and
  rename only the chart, that also works.
- **Maturity.** The merged pack re-enters at `experimental` on the pack
  dashboard until the integration tests cover the combined chart, then follows
  the normal promotion path.

## How to land it without an unreviewable PR

1. **PR 1 (this proposal).** `docs/proposals/0001-*.md` plus `ARCHITECTURE.md`
   into provenance-collector-pack. Discussion happens on the PR. Nothing else
   changes.
2. **PR 2 (collector as a library/binary).** Small Go change: make
   `cmd/provenance-collector` support `--output -` (stdout) and a `--once`
   single-run mode if not already present, and publish the binary as a release
   asset. This is useful on its own.
3. **Import.** With agreement on 1 and 2, bring the posture pack tree in with
   `git merge --allow-unrelated-histories` (history preserved from both sides),
   moving the Go code to `collector/` and keeping `frontend/` only until the
   nebari-design UI replaces it in the same PR. Maintainers review structure,
   chart values compatibility and the compatibility tests, not every line.
4. **Follow-ups.** Worker uses the collector binary; delete the Python provenance
   port; docs site gains the compliance pages; `tracked-packs.yaml` updated;
   old chart name deprecated for one release.

Alternative if the maintainers prefer: transfer `nebari-security-posture-pack`
into `nebari-dev` as a new repo, keep provenance-collector-pack as is, and have
the posture pack consume its report API. This is less work but leaves two packs
with overlapping discovery code.

## Compatibility and migration notes for existing users

- Grafana Infinity URL changes only in the Service name:
  `http://<release>-web-internal.<ns>.svc:8080/api/reports/latest`.
- `persistence.mode` (http/pvc/configmap) is replaced by Postgres; report
  history is retained per scan.
- The CronJob schedule maps to `scanner.intervalHours`.
- Auth: the SPA PKCE flow is replaced by gateway enforcement plus an in-app JWT
  check, gated to `adminGroups`.

## Open questions for the maintainers

- Keep the Go collector as the provenance engine (preferred) or accept the
  Python port?
- Repo rename vs chart-only rename.
- Who owns the merged pack on the dashboard (`owner`, `product_owner`).
