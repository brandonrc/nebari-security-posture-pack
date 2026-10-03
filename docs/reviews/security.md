# Security review: `security-posture-merge` (provenance-collector-pack + security-posture pack)

Reviewer role: application/platform security. Scope: code at `e86c9af` plus the live `security-posture` release on grace (read-only kubectl). Nothing was modified.

## TL;DR

The application-layer auth is solid: JWKS verification with an asymmetric-only algorithm allowlist, required `exp` and `iss`, fail-closed 401/403, and admin checks enforced in the API whatever the gateway does. The containers are well hardened.

The risk is in the platform blast radius.

- **With `provenance.helmReleases.enabled` on (as it is on grace), the api and worker ServiceAccount can read every Secret in the cluster.** The worker parses untrusted image content and registry responses, so one parser bug turns into cluster compromise.
- **Scan results can be forged.** The pack scans mirrored images by a mutable tag in a registry that anyone can write to without authentication.
- **The Python provenance and Helm paths have several unbounded-memory and SSRF problems.**
- **The documented auth contract does not match the code in one important place:** an empty `auth.issuers` list accepts any issuer, while the chart says such tokens are rejected.

None of this blocks merging behind defaults (helm-releases and the compat listener are both off by default). But the grace overlay turns both risky features on, and the PR describes the pack as admin-only, which the compat listener and the Secret RBAC quietly undermine.

---

## Critical

### C1. Cluster-wide `secrets get/list` on the api and worker ServiceAccount
- **Evidence:**
  - `chart/templates/rbac.yaml:62-95` (ClusterRole `…-helm-releases`, `secrets: [get, list]`, no namespace or name restriction). It is bound to the single SA that both pods use (`api.yaml:30-32` and `worker.yaml:29` set `automountServiceAccountToken: true`).
  - It is turned on in `deploy/grace/values.yaml` (`provenance.helmReleases.enabled: true`).
  - Live check: `kubectl auth can-i list secrets -A --as=system:serviceaccount:security-posture:security-posture` returns **yes**. The Secrets reachable on grace include `cert-manager/nebari-ca-secret` (the cluster CA private key), `keycloak/keycloak-admin-credentials` (Keycloak master admin), the envoy-gateway xDS TLS keys, every NebariApp OIDC client secret, DB credentials, and 71 Helm release payloads (rendered values often hold plaintext passwords).
  - DESIGN §3 still says "NO secrets access cluster-wide". The chart comment admits RBAC cannot filter by label.
- **Impact:** The worker runs trivy, grype, clairctl, skopeo, cosign and the Go collector against attacker-chosen images and registries (any pod spec in any namespace that is not excluded). A memory-safety or parser bug in any of them, or a Python deserialization bug, gives read access to the CA key and the Keycloak master admin. From there an attacker can mint admin tokens for every Nebari app, MITM any TLS host and in practice take over the cluster. The api pod, which is reachable from the internet through the UI proxy, holds the same token although it needs neither Secrets nor Keycloak.
- **Fix (in order of preference):**
  1. Drop the Python Helm path and let the Go collector run as a separate **Job/CronJob with its own SA**. The worker and api should not hold that token.
  2. If Helm discovery must stay in-process, use a namespaced `Role` per opted-in namespace (a values list), or `resourceNames` generated from a pre-install lookup. Never a ClusterRole.
  3. Split ServiceAccounts in every case: `api` gets `nebariapps` and `namespaces` read only; `worker-scan` gets pods and workloads read; `controls` gets the controls ClusterRole plus the single Keycloak Secret.
  4. Add a render-time `fail` unless `provenance.helmReleases.acknowledgeClusterSecretRead: true`, and update DESIGN §3.

### C2. Scan integrity: scanners read a mutable tag in an anonymously writable registry, and the "already mirrored" short-circuit trusts it
- **Evidence:**
  - `images.py:149-156`: the mirror destination is `…/posture-mirror/<reg>/<repo>:sha256-<hex>`, a **tag** and not `@digest`.
  - `mirror.py:73-74`: `if ref.digest and await self.exists(dest…)` returns the cached target with no check that the manifest digest matches.
  - The scanners then pull `target.ref` (`worker.py:505`).
  - Mirror registry defaults: `registry.container-registry.svc:5000` with `insecure: true`. On grace it is a **NodePort 32000** with no auth (`kubectl -n container-registry get svc`). The pack's own `reg-access-restricted` assertion flags exactly this.
- **Exploit:** Any principal that can push to the registry (anonymous on grace, from any pod or the LAN via the NodePort) pushes a clean image to `posture-mirror/docker.io/acme/app:sha256-<digest of the real, vulnerable image>`. Every later scan of that workload reports zero findings, and that result flows into the POA&M, SAR and OSCAL-AR. The skopeo policy `insecureAcceptAnything` (`mirror.py:16`) means nothing catches it.
- **Fix:**
  - Copy with `skopeo copy --digestfile` and scan `dest@<that digest>`.
  - On reuse, `skopeo inspect --raw` the destination and compare against the expected source platform-manifest digest. Better, record the copied digest in the DB and scan by digest.
  - Require auth on the mirror (pass `--dest-creds` from a Secret), or a dedicated in-namespace registry that only the worker can reach (NetworkPolicy).
  - Document that a writable mirror is a trust anchor.

---

## High

### H1. Empty `auth.issuers` accepts **any** issuer, but the chart and NOTES say every token is rejected
- **Evidence:**
  - `auth.py:151-153`: `if issuers and iss not in issuers: raise`. With an empty list there is no check, only a warning at line 122.
  - `chart/values.yaml:115-118` says "REQUIRED … with an empty list the API rejects every token", and `NOTES.txt:36-39` says the same.
  - The chart default is `issuers: []`.
  - No `aud` or `azp` check: `oidc_audience` defaults to `None` (`config.py:35`), the chart never sets `OIDC_AUDIENCE`, and the chart and live SecurityPolicy JWT providers set no `audiences`.
- **Impact:** Signatures are still pinned to the nebari-realm JWKS, so this is token confusion, not forgery. Any token minted by that realm for **any client** is accepted if it carries `groups: [admin]`: access tokens, ID tokens, and tokens issued to third-party NebariApps. A NebariApp deployed with `forwardAccessToken: true` receives an admin's access token when the admin visits it and can replay it. Today the gateway's OIDC cookie requirement blocks outside replay, unless `adminGate.securityPolicy.passThroughAuthHeader: true` is set (a supported value). The API's in-cluster NetworkPolicy is the only other barrier.
- **Fix:**
  - Fail closed: reject when `oidc_issuers` is empty and `auth_mode=oidc`, raising at startup, and make the chart `required` it.
  - Add an `azp`/`aud` check against the operator-provisioned client id (`<ns>-<fullname>`), carried in values as `auth.audience` or `auth.authorizedParty`. Add `audiences` to the rendered SecurityPolicy JWT provider.
  - Add a regression test for the empty-issuers case.

### H2. The unauthenticated compat listener turns admin-only inventory into data any Grafana user can read
- **Evidence:**
  - `provenance_compat.py:204-209, 224-235` binds `0.0.0.0:8081` with no auth (`/api/reports*`, `/api/export`).
  - `provenance-internal-service.yaml:29-54`: the NetworkPolicy allows **whole namespaces** (`monitoring`, `observability` on grace) and is only rendered when `networkPolicy.enabled`. With NetworkPolicy off, or on a CNI that does not enforce policies (flannel, some k3s/kind setups), every pod in the cluster can read it, including JupyterHub user pods.
  - On grace the Grafana NebariApp admits `[admin viewer]`.
- **Data exposed:** The full image inventory per namespace and workload (spec image, digest), signature, SBOM and provenance status, available updates, and Helm release names, charts and versions (`report.py:147-215`). No CVE detail, but it is a ready target list ("unsigned, two majors behind, in namespace X").
- **Abuse:** A Grafana viewer reads it through an Infinity dashboard, or a Grafana editor queries the URL directly. A compromised Promtail, Loki or node-exporter pod in those namespaces reads it directly.
- **DoS:** `/api/reports` runs `load_report` for up to 50 scans per call (`provenance_compat.py:72-84`) on the **same event loop** as the authenticated API, with no rate limit.
- **Fix:**
  - Require a static bearer token from a Secret, mounted into Grafana's datasource as a header, or a TokenReview of the caller's SA token.
  - Narrow the NetworkPolicy to a `podSelector` for Grafana pods, not whole namespaces.
  - `fail` the render when `internalService.enabled && !networkPolicy.enabled`.
  - Cache the list endpoint and cap scans per call.
  - Fix the DESIGN §12 heading, which still says "no auth difference".

### H3. The registry client: SSRF, token reflection and unbounded response bodies, all driven by pod specs
- **Evidence:** `provenance/registry.py`:
  - `:180`: `client.get(realm, …)` uses a `realm` taken from the registry's `WWW-Authenticate` header, with no host check. Whatever comes back as `token`/`access_token` is then sent as `Authorization: Bearer` to the registry.
  - `:154`: `follow_redirects=True`.
  - `:227, :250`: `resp.content[:MAX]` reads the **whole** body before truncating. Tag listing (`:252-265`) accepts up to 50 unbounded pages.
  - Registry hosts come from `parse_image_ref`, which accepts any host containing `.` or `:` (`images.py:48-49, 76-77`).
- **Exploit:** Anyone who can create a pod, even one that never runs (`image: evil.example/x:1`), makes the worker:
  - send GETs to arbitrary in-cluster or metadata URLs (blind SSRF);
  - reflect any JSON `token` field from an internal service back to the attacker's registry;
  - stream multi-GB manifests, blobs or tags into memory until the worker is OOM-killed. The worker is a single replica, so scanning stops and the pack's own `pack-scan-recent` control fails.
- **Fix:**
  - Stream with `client.stream()` and abort past the cap.
  - Only follow a realm on the same registrable domain or an allowlist. Never follow redirects to RFC1918, link-local or loopback addresses unless the registry is in `insecure_hosts`.
  - Cap tag pages by bytes.
  - Add worker egress NetworkPolicy (deny 169.254.0.0/16 and the cluster CIDR except the named services).

---

## Medium

### M1. Gzip bomb in Helm release Secrets
`helm.py:67-71`: `gzip.decompress(raw)` has no output cap, and `json.loads` follows. The Go collector path (Helm's own decoder) has the same problem. Anyone who can create a Secret labelled `owner=helm` in any namespace, which namespace admins and CI pipelines can do, can plant about 1 MiB that expands to about 1 GB. Parsing it into Python objects takes several GB and OOM-kills the worker on every scan until someone deletes the Secret.

**Fix:** Decompress with `zlib.decompressobj().decompress(data, MAX)` (for example 32 MiB) and refuse past the cap. Skip Secrets larger than 1 MiB. Set `GOMEMLIMIT` and run the collector in its own cgroup (a Job).

### M2. Argument injection hardening: image refs reach CLIs as the last positional with no `--` separator
- **Evidence:**
  - `parse_image_ref` does not validate the **registry** or the **tag**. Verified: `--server=evil.example/x` → `--server=evil.example/x:latest`, and `a.b/x:--help` is accepted.
  - These refs reach `trivy … <ref>` (`trivy.py:100-107`), `cosign verify … <ref>` (`checks.py:376-388`) and `clairctl … report … <ref>` (`clair.py:236-238`) whenever the mirror falls back to the original ref, which it does for invalid refs.
  - Kubernetes accepts any non-whitespace `image` string; the pod just fails to pull, but the inventory still records it.
  - skopeo is safe (`docker://` prefix) and so is grype (`registry:` prefix).
- **Impact today:** Limited. One token can override one flag (for example `--server=`), and the CLI then fails for lack of a positional argument. It is fragile, and a single CLI change could make it exploitable.

**Fix:** Validate against the distribution reference grammar (registry `[A-Za-z0-9.-]+(:port)?`, tag `[\w][\w.-]{0,127}`), reject refs starting with `-`, and insert `--` before positional refs for trivy, cosign and clairctl.

### M3. Secrets inherited by every scanner subprocess
`scanners/base.py:78` copies all of `os.environ`, and so does `collector.py:87`. As a result `DB_PASSWORD` and `DATABASE_URL` (with the password expanded by the kubelet), plus any extra env, reach trivy, grype, clairctl, cosign, skopeo and the Go collector, the processes that parse untrusted input.

**Fix:** Pass a minimal allowlisted env (`PATH`, `HOME`, `TMPDIR`, `SSL_CERT_FILE`, `DOCKER_CONFIG`, tool-specific vars). Mount the DB password as a file and have the app read it.

### M4. Keycloak: realm-admin (write) credentials used for read-only assertions
`context.py:167-207` and the values default `nebari-realm-admin-credentials`. Problems:
- The assertions only need `view-realm`, `view-users` and `view-events`.
- With no `adminRealm`, `_login` retries the same password against `master` (`context.py:192`).
- The password grant goes over plaintext HTTP inside the cluster (`controls.keycloak.url: http://…`), so `verifyTls: true` has no effect.
- On grace, C1 makes the narrow `Role` for this one Secret pointless.

**Fix:** Ship a dedicated confidential service-account client (`client_credentials`) with only the `realm-management` view roles and its own Secret, pin `adminRealm`, and use HTTPS or document the risk.

### M5. CSV/XLSX formula injection in compliance reports
`reports/poam.py`, `inventory.py`, `vuln_export.py`, `routers/export.py` and the compat `export_csv` write untrusted strings with no neutralisation: image tags (any characters after the colon, see M2), workload and Helm chart names, scanner titles. openpyxl stores strings that start with `=` as formulas. A pod with `image: x.io/a:=HYPERLINK(...)` ends up as a live formula in the POA&M or inventory workbook that an assessor opens.

**Fix:** Prefix cells starting with `= + - @ \t \r` with `'`. For openpyxl, set `cell.data_type = "s"` explicitly.

### M6. No security headers on the UI; CSRF defences are inconsistent
`ui/docker/default.conf.template` sets no CSP, `frame-ancestors` or `X-Frame-Options`, `Referrer-Policy` or `X-Content-Type-Options` on HTML. The compat `POST /api/scan` requires `Sec-Fetch-Site: same-origin`, but the native POSTs do not:
- `POST /api/v1/scans`: the body is optional, so an empty `text/plain` form POST passes FastAPI.
- `POST /api/v1/compliance/assertions/run`: no body.

Cookie auth is effectively in force, because Envoy injects the bearer from the session cookie. SameSite on the Envoy session cookie is not set explicitly; browsers then default to Lax, which leaves same-site sibling apps (`*.100-89-230-107.sslip.io`) able to fire these POSTs. Impact is low (trigger a scan or engine run), but the gap is real.

**Fix:**
- A middleware that rejects unsafe methods unless `Sec-Fetch-Site` is `same-origin` (or `Origin` matches the host), or unless the request carries a bearer with no cookie.
- Add a CSP, `frame-ancestors 'none'` and the other headers in nginx.
- Set `cookieConfig.sameSite: Strict` where Envoy Gateway supports it.

---

## Low

- **L1. Group-name collision.** `normalize_groups` (`auth.py:107-114`) plus a mapper with `full.path=false` (grace) means a **subgroup** named `admin` under any parent grants pack admin. Anyone who can create subgroups in Keycloak (delegated group managers) can escalate. Prefer `full.path=true` and match `/admin` exactly. Document it.
- **L2. Logout is local only.** `endSessionEndpoint: false` by default means `/logout` clears the Envoy cookies but the Keycloak SSO session survives, so the next visit re-authenticates silently. Enable it on Envoy Gateway ≥ 1.5.
- **L3. JWKS over plain HTTP in-cluster** (`auth.jwksUrl: http://keycloak…`). Anyone who can MITM the pod network can substitute signing keys. Calico mitigates ARP spoofing; still prefer HTTPS or a pinned key. Also, the JWKS lock is held during the fetch (10 s timeout), so a slow Keycloak stalls every request.
- **L4. `AUTH_MODE=disabled` only warns.** The chart renders it with a NOTES warning, and the api still listens on `0.0.0.0`. Refuse to start unless an explicit `ALLOW_INSECURE_DEV=1` is also set.
- **L5. Signature trust anchors are editable at runtime.** `PUT /settings` lets any pack admin change `provenance.cosignPublicKey`, `…IdentityRegexp` and `…IssuerRegexp` (`app_settings.py:57-59`), contradicting `values.yaml:200` ("every toggle except the cosign key material"). Setting `.*`/`.*` makes every keyless-signed image "verified". A file path is also accepted (`collector.py:128`).
- **L6. Global insecure-registry env.** `worker.yaml:78-83` exports `GRYPE_REGISTRY_INSECURE_USE_HTTP` and `TRIVY_INSECURE` set to `mirror.insecure` globally. The adapters override both per call (good), but any new caller that inherits the env silently skips TLS. Remove the globals.
- **L7. Report deletion is not attributed.** `routers/reports.py:132-142` never logs the user who deleted. Pruning keeps 50 per type and deletes ATO evidence silently. Reports on `microk8s-hostpath` sit unencrypted on the node, and they contain the names of admins without MFA (`kc-admin-mfa` evidence). Log deletions with the user, consider immutability or retention by scan, and add a values knob for history retention (scans, findings and consensus are kept forever; raw JSON is nulled after 14 days, `worker.py:677-679`).
- **L8. Inert `ui.readOnlyRootFilesystem`.** `ui.yaml:62` uses `merge (dict readOnly false) containerSecurityContext`. Sprig/mergo overwrites zero values, so `false` never applies (it fails safe, and live shows `true`). The values comment "writable by default" (`values.yaml:433-435`) is wrong.
- **L9. No trivy server token or clair auth.** Only the NetworkPolicy protects them, which is fine with an enforcing CNI. Add `--token` for trivy.

---

## Container hardening and the pack's own checks

**Hardening is good.** Every pod is `runAsNonRoot` with fixed UIDs, `seccompProfile: RuntimeDefault`, `allowPrivilegeEscalation: false`, `drop: [ALL]` and `readOnlyRootFilesystem: true` (all verified live). trivy, clair, postgres and ui use the `default` SA with `automountServiceAccountToken: false`. The images run as `USER 10001`/`101`.

**The pack fails its own posture checks on grace.** From the live specs and namespace:

| Own check / assertion | Object | Result | STIG / 800-53 |
|---|---|---|---|
| `no-netpol` | `security-posture-worker` (no NetworkPolicy selects it) | **fail** | V-233029, V-233030, V-233273 |
| `no-liveness-probe`, `no-readiness-probe` | worker (it serves `/healthz` on :9000 but the chart sets no probes) | **fail** | V-233273 |
| `k8s-pod-security-admission` | namespace `security-posture` has no `pod-security.kubernetes.io/enforce` label | **fail** | CM-6, CM-7 |
| `k8s-default-deny-ingress` | no `podSelector: {}` deny policy in the namespace | **fail** | SC-7(5) |
| `k8s-default-sa-automount` | `default` SA in the namespace has automount unset | **fail** | AC-6(10) |
| `reg-access-restricted` | the mirror registry the pack *requires* (NodePort 32000, anonymous) | **fail** | CM-14, SR-4 |
| supply-chain score | the pack's own grace images (`localhost:32000/…`, built locally, unsigned, no SBOM or provenance attached) | ≈ −75 to −85 per image → **F** | SR-4, CM-14; V-233065 |
| `mutable-tag` | `postgres:16-alpine` (floating) | passes, because the check only flags `latest` or no tag. **Check gap.** | V-233065 |
| `automount-sa-token` | api and worker mount a token with cluster-wide Secret read | passes, because the check only looks at the `default` SA. **Check gap.** | V-233163 |

Recommended additions to the pack's checks:
- An RBAC assertion: "no non-system SA can `list secrets` cluster-wide". That would flag C1 on the pack itself.
- Treat any tag without a digest as mutable for infrastructure images.

---

## Supply chain of the pack

**Good:**
- CI actions are pinned by SHA.
- `build-image.yaml` builds with `sbom: true` and `provenance: mode=max`, and keyless-signs both registries by digest.
- Scanner binaries are SHA-256-checked (`Dockerfile.worker` tools stage).
- The Go build uses `go.sum`, and the UI uses `npm ci` with a lockfile.

**Gaps:**
- **Python dependencies are not locked in the images.** `pip install .` (`Dockerfile.api:12`, `Dockerfile.worker:31`) ignores `uv.lock`, so transitive dependencies resolve at build time. Use `uv sync --frozen` or `pip install --require-hashes -r` an exported lock.
- **Base images are tag-only:** `python:3.12-slim-bookworm`, `golang:1.26`, `node:22-alpine`, `nginxinc/nginx-unprivileged:1.27-alpine`, and in the chart `postgres:16-alpine`, `aquasec/trivy:0.75.0`, `quay.io/projectquay/clair:4.9.0`. `skopeo` comes from apt, unpinned. Pin by digest (Renovate can keep them current). The chart supports `digest:`, so set it in the release.
- `release.yaml` uses `nebari-dev/helm-repository/.github/actions/sync-chart@main`, which is **unpinned**. The chart and the collector release tarballs are not signed; there is only a `checksums.txt`. Sign them with cosign (`sign-blob`) and publish a Helm `.prov` file.
- **Grace runs locally built, unsigned images** (`deploy/grace/build-push.sh` → `localhost:32000`, `pullPolicy: Always`, tag-only). Anyone who can push to the anonymous registry can replace the pack's own images at the next restart, which combined with C1 means cluster compromise. Deploy CI-built, digest-pinned images, or at least pin the grace overlay to digests.
- **mirror.gcr.io:** neither this branch nor its history references it (`git log -S` finds nothing). The Docker Hub rate-limit answer here is the skopeo mirror plus `REGISTRY_AUTH_FILE`. If grace's containerd uses mirror.gcr.io as a node-level mirror, pulls by digest stay integrity-safe, but tag pulls trust Google's cache, and the pack's update checks will still hit Docker Hub directly and come back `unknown`.

---

## Verdict

**The merge is sound in shape, but it is not safe to ship with the grace overlay's settings.**

- **What holds up:** the API's own JWT and admin enforcement, the gateway-agnostic three-layer gate, and container hardening are all well done.
- **What is unsound:** the security model assumes the pack is "admin-only, read-only", but three merged features break that assumption:
  - cluster-wide Secret read on the shared SA (C1);
  - a tag-addressed, anonymously writable scan mirror (C2);
  - an unauthenticated inventory listener (H2).

  Together with H1 (issuer and audience) and H3 (registry SSRF/OOM), a namespace-level tenant can blind or falsify the tool, and a parser exploit in the worker reaches the CA key and the Keycloak master admin.

**Before merge:**
- C2: scan by digest and verify on reuse.
- H1: fail closed on empty issuers and add an `azp` check, plus a test.
- Split ServiceAccounts so the api holds no Secret or Keycloak access.
- Make `helmReleases` and `internalService` require explicit acknowledgement values, with the NetworkPolicy requirement enforced.
- Fix the DESIGN §3 and §12 text.

**Can follow:** H3, M1–M6 and the Lows.
