# Supply-chain provenance (DESIGN §12)

The security posture pack does everything
[provenance-collector-pack](https://github.com/nebari-dev/provenance-collector-pack)
does (signatures, SBOM and SLSA provenance attestations, image update checks, Helm
releases) as a worker stage, scores it, tags it with 800-53 controls, and serves
their API so their Grafana dashboards and consumers keep working. This page covers
what is compatible, where we differ, and how to switch a Grafana dashboard over.

## How it runs

The worker's `provenance` stage starts right after inventory and runs while the CVE
scanners run. Per unique image digest it does the following:

| check | how |
|---|---|
| signature | Looks for the legacy cosign `sha256-<hex>.sig` tag and for sigstore bundle / cosign OCI-1.1 signature referrers. When a key or keyless identity is configured it then runs `cosign verify` (pinned cosign v3.1.3 in the worker image). |
| SBOM | Looks in four places, in order: OCI referrers (the referrers API, then the `sha256-<hex>` fallback tag), BuildKit attestation manifests inside the image index, cosign `.att` (the DSSE payload is decoded), and the cosign `.sbom` tag. The format is `spdx` or `cyclonedx`. |
| SLSA provenance | Same places as SBOM. Accepts predicate types `https://slsa.dev/provenance/*` and `https://in-toto.io/provenance/*`. |
| updates | Lists the repository's tags through the registry API. Parsing and ordering are compatible with Masterminds/semver v3 `NewVersion`, but only *version-like* tags with the current tag's variant suffix are candidates (see "Update candidates" below). Honours `updateLevel` (patch / minor / major) and `skipPrerelease`. |
| Helm releases | Reads `sh.helm.release.v1.*` Secrets (label `owner=helm`) and keeps the latest revision of every release in any status, like `helm list --all`. Optionally checks for chart updates against `provenance.helmReleases.chartRepos`. |

Results are stored per image per scan in `image_provenance`, with a denormalized copy in
`images.provenance`. Helm releases go in `helm_releases` per scan (migration
`0002_provenance`). Signature, SBOM and provenance results are reused per digest for
`recheckHours` (default 24), unless the scan is forced or the cosign / check
configuration changed. Tags are re-listed on every scan.

Registry access goes through `posture.provenance.registry`, a small async OCI client.
It uses anonymous bearer tokens, or the docker `config.json` from `REGISTRY_AUTH_FILE` /
`DOCKER_CONFIG`, and talks plain http to the mirror and `MIRROR_REWRITE` targets.
Probes for tags that usually don't exist use HEAD first, because Docker Hub does not
count HEAD requests against its pull rate limit.

## Scoring and controls

See `SCORING.md`. Each image starts at 100 and loses points as follows, with a floor of 0:

| finding | penalty |
|---|---|
| unsigned | −40 |
| signed but not verified | −20 |
| no SBOM | −20 |
| no SLSA provenance | −15 |
| update available | −15 (−25 when a major version behind) |
| mutable tag without a digest pin | −10 (per container spec) |

`supplyChainScore` is the container-weighted mean over running containers. The cluster
score is `0.6 vuln + 0.25 posture + 0.15 supplyChain`. If the stage is disabled or has
no data yet, the cluster score is `0.7 / 0.3`.

Two kinds of result never cost points:
- A check that is switched off contributes nothing.
- An image whose registry was unreachable or rate-limited is *unknown*, not failed. It
  is not cached, so the next scan retries it.

Control tags live in `reports/data/controls.yaml` under `provenance:`:

| finding | controls |
|---|---|
| `unsigned` | CM-14, SR-4, SR-11 |
| `unverified` | CM-14, SR-11 |
| `no-sbom` | SR-4, SA-8(3), CM-8 |
| `no-provenance` | SR-3, SR-4, SA-10 |
| `update-available`, `major-update-available` | SI-2 |
| `mutable-tag` | CM-2, CM-14 |
| `helm-release-behind` | SI-2, CM-3 |

## Configuration

The chart's `provenance:` block uses their `config:` key names where they exist.

| theirs (`config.*`) | ours (`provenance.*`) | env | runtime setting (`PUT /api/v1/settings` `provenance`) |
|---|---|---|---|
| `verifySignatures` | `verifySignatures` | `PROVENANCE_VERIFY_SIGNATURES` | `verifySignatures` |
| `cosignPublicKey` (path / KMS URI) | `cosignPublicKey` (PEM text, path, KMS or remote URI) or `cosign.existingSecret` (key `cosign.pub`) | `PROVENANCE_COSIGN_PUBLIC_KEY` | `cosignPublicKey` |
| none | `cosign.certificateIdentityRegexp` / `certificateOidcIssuerRegexp` (keyless) | `PROVENANCE_COSIGN_CERTIFICATE_*_REGEXP` | `cosignCertificateIdentityRegexp`, `cosignCertificateOidcIssuerRegexp` |
| `checkSBOM` | `checkSBOM` | `PROVENANCE_CHECK_SBOM` | `checkSbom` |
| `checkProvenance` | `checkProvenance` | `PROVENANCE_CHECK_PROVENANCE` | `checkProvenance` |
| `checkUpdates` | `checkUpdates` | `PROVENANCE_CHECK_UPDATES` | `checkUpdates` |
| `updateLevel` | `updateLevel` | `PROVENANCE_UPDATE_LEVEL` | `updateLevel` |
| `skipPrerelease` | `skipPrerelease` | `PROVENANCE_SKIP_PRERELEASE` | `skipPrerelease` |
| `helmEnabled` (default true) | `helmReleases.enabled` (default **false**, adds RBAC) | `PROVENANCE_HELM_ENABLED` | `helmReleases` |
| `namespaces` / `excludeNamespaces` | `scanner.excludedNamespaces` (shared with the CVE scan) | `EXCLUDED_NAMESPACES` | `excludedNamespaces` |
| `registryTimeout` | `registryTimeoutSeconds` | `PROVENANCE_REGISTRY_TIMEOUT` | not editable |
| `clusterName` | `CLUSTER_NAME` / settings `systemName` | | `systemName` |
| `schedule`, `reportRetention`, `persistence.*` | the scan schedule (`scanner.intervalHours`) and scan retention (last 10 completed scans) | | |
| none | `enabled`, `recheckHours`, `concurrency`, `helmReleases.chartRepos` | `PROVENANCE_ENABLED`, `PROVENANCE_RECHECK_HOURS`, `PROVENANCE_CONCURRENCY`, `PROVENANCE_HELM_CHART_REPOS` | `enabled`, `recheckHours` |

Keyless verification for Kubernetes release images
(`registry.k8s.io`) needs `certificateIdentityRegexp: ^krel-trust@k8s-releng-prod\.iam\.gserviceaccount\.com$`
and `certificateOidcIssuerRegexp: ^https://accounts\.google\.com$`. The worker needs
egress to the Sigstore TUF / Rekor endpoints. The TUF cache is `/cache/sigstore`.

**Helm RBAC.** `provenance.helmReleases.enabled=true` renders an extra ClusterRole with
cluster-wide `secrets` get/list. RBAC cannot filter by label, so this covers every
Secret, not only Helm's. Their chart grants the same thing. With the value off,
discovery logs `helm release discovery needs secrets list RBAC` and the rest of the
stage still runs.

## Compatible API

These routes are served by our API outside `/api/v1`, so `ui` nginx proxies them
unchanged:

| their endpoint | here | notes |
|---|---|---|
| `GET /api/reports` | ✓ | `[{filename, generatedAt, summary, clusterName?}]`, newest first. There is one report per completed scan that has provenance results (`provenance-YYYYMMDD-HHMMSS.json` from the scan's finish time). An empty list is `[]`. |
| `GET /api/reports/latest`, `/api/reports/provenance-latest.json`, `/api/reports/{filename}` | ✓ | Their report document. Field names, field order, `omitempty` and Go `MarshalIndent` formatting (HTML-escaped `<>&`, RFC 3339 nano time) all match. Errors are `text/plain` (`report not found`, `invalid filename`) with their status codes. |
| `GET /api/export?format=csv\|markdown\|md&filename=` | ✓ | Byte-compatible CSV / Markdown. `format=json` (extra) returns the report. |
| `GET /api/me` | ✓ | `{authEnabled, email?, groups?, canRunScan, features:{timelineDeltas}}`. Anonymous callers get an answer. `canRunScan` is true for members of our admin group. |
| `POST /api/scan` | ✓ | Same `Sec-Fetch-Site: same-origin` CSRF rule and admin check. Enqueues one of our scans and returns `{jobName: "posture-scan-<id>", namespace, scanId}`. A scan already queued or running returns 409. |
| `GET /healthz` | ✓ | `{"status":"ok"}` |
| `POST /internal/reports` (collector upload) | ✗ | Not needed: the worker writes the DB directly. |

Auth: on the main listener, `/api/reports*` and `/api/export` need our admin group.
The rest of our API does too. Theirs only needs any authenticated user.

Native endpoints: `GET /api/v1/supply-chain` returns counts, score/grade, check toggles
and lists (`unsigned`, `unverified`, `outdated`, `withoutSbom`, `withoutProvenance`).
`GET /api/v1/helm-releases?namespace=` returns their `HelmRecord` plus `revision`,
`lastDeployed`, `chartSource` and `scanId`. `/api/v1/summary` gains `supplyChainScore`
and `supplyChain`. `ImageSummary.provenance` carries `{checkedAt, signature, sbom,
provenance, update, updates{tag: UpdateInfo}, mutableTag, score, grade, findings[],
deductions[{reason, points}], controls[], error}`. The nested objects are their JSON
shapes.

## Grafana (Infinity datasource)

Their dashboards fetch `http://provenance-collector-web.provenance-system.svc:8080/api/reports/latest`
without auth. To serve the same thing here:

```yaml
provenance:
  compat:
    internalService:
      enabled: true
      allowedNamespaces: [monitoring]   # Grafana's namespace (NetworkPolicy)
      # name: provenance-collector-web  # optional: keep the old Service host name
```

This does two things:

- **A second listener in the api pod.** The api process starts it on `:8081`
  (`PROVENANCE_COMPAT_INTERNAL_PORT`, same event loop and DB pool). It serves only the
  read endpoints (`/api/reports`, `/api/reports/{filename}`, `/api/export`, `/healthz`)
  and has no auth. It cannot reach `/api/v1`, `/api/scan` or `/api/me`.
- **A ClusterIP Service in front of it.** `<fullname>-web-internal:8080` points at that
  listener. A NetworkPolicy admits only `allowedNamespaces` on that port. The
  NebariApp/gateway never routes it.

Change the dashboard's datasource URLs to:

```
http://<fullname>-web-internal.<release-namespace>.svc:8080/api/reports/latest
# e.g. on grace: http://security-posture-web-internal.security-posture.svc:8080/api/reports/latest
```

The `root_selector`s (`""`, `images`, `helmReleases`) and column selectors
(`summary.*`, `signature.signed`, `sbom.hasSBOM`, `update.latestInMajor`, …) work
unchanged. With `internalService.name: provenance-collector-web`, a release installed in
`provenance-system` keeps the old URL byte-for-byte.

## Differences from provenance-collector-pack

- **Workload.** `workload` is the resolved controller: Deployment / CronJob, not the
  ReplicaSet / Job their discovery reports. `kind`/`name` keep the same types.
- **Digest.** `digest` is the digest actually running (pod `imageID`). Theirs resolves
  the tag at report time.
- **Failed verification.** It keeps `signed: true`, with `verified: false` and
  `error: "verification failed: …"`. Theirs reports `signed: false`. `signedImages`
  therefore counts signatures that exist.
- **Signature and attestation sources.** We also detect sigstore-bundle /
  OCI-1.1 signatures, the native referrers API, cosign `.att` payloads (SLSA and SBOM)
  and `.sbom` tags. Theirs only reads the fallback tag, BuildKit index attestations and
  `.sig` / `.att` (SBOM only).
- **Report history.** History is per scan, retained for the last 10 completed scans,
  not `reportRetention` files on a PVC. `generatedAt` is the scan finish time.
- **Version string.** `collectorVersion` is `<pack version>+posture`.
- **Chart updates.** Helm releases get `update` when `helmReleases.chartRepos` knows the
  chart. Theirs never fills it, so `helmReleasesWithUpdates` is always 0 there.
- **Helm discovery.** It is off by default because of the cluster-wide Secrets RBAC.
- **Update candidates.** Theirs accepts every tag Masterminds/semver parses, so CI build
  numbers and dates win `newestAvailable` (cert-manager `v1.16.2` -> `608111629`,
  grafana -> `9799770991`) and count as major updates, and `postgres:16-alpine` is
  offered `18.6` (a different image variant). Ours keeps their parsing and ordering but
  filters the candidate tags first:
  - *Version-like* only: optional `v`, 2-3 dot-separated numeric components (a 4th
    numeric one is tolerated and orders after the 3rd), optional `-suffix` / `+build`.
    Rejected: bare integers (`16`, `608111629`), a MAJOR with more than 4 digits,
    dates (`2024-01-15`, `2024.01.15`, `20240115`; allowed when the current tag is
    itself a date-style CalVer tag) and non-numeric 4th parts (`2.10.0.d5b5a1-py38`).
  - Major-jump guard: candidates whose MAJOR is more than `provenance.maxMajorJump`
    (default 50, `PROVENANCE_MAX_MAJOR_JUMP`, `0` = off) above the current one.
  - Same variant: a suffix is a *prerelease* when one of its identifiers is
    alpha/beta/rc/pre/preview/dev/snapshot/canary/nightly/git (optionally with a number);
    any other suffix is an image *variant* (`alpine`, `py3.12`, `distroless`,
    `debian-12-r5`, a build number). Candidates must have the current tag's variant
    shape (digits abstracted: `alpine3.20` = `alpine#.#`), so `16-alpine` only sees
    `16.6-alpine` / `17.2-alpine` and `16.4` never sees `16.6-alpine`. Prereleases
    follow `skipPrerelease` as before.

  The current tag still short-circuits exactly like theirs (`latest` / unparseable tags
  are not listed). Chart versions go through the same filter.
- **Not implemented.** `provenance.useSbomForGrype` (feeding attestation SBOMs to
  grype) is not implemented yet. Their ConfigMap output mode, upload endpoint, retention
  pruning and frontend branding have no equivalent.
