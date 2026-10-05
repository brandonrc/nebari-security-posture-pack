# nebari-security-posture-pack

An **admin-only** [Nebari](https://nebari.dev) software pack that continuously
inventories every container running in the cluster, scans each unique image
with **Trivy, Grype and Clair**, cross-correlates the three result sets, audits
workload configuration, and presents one **Security Posture rating** (0–100,
grade A–F) with drill-down by image, CVE, workload, namespace and check.

Status: **experimental** (v0.1). Design contract: [docs/DESIGN.md](docs/DESIGN.md).

## How it works

> The 30,000-foot view, with diagrams of the three evidence layers, the control-inheritance model and the continuous-ATO loop, is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```
inventory (K8s API) -> unique images by digest -> mirror (skopeo) -> trivy + grype + clair
   -> normalise -> correlate (consensus per CVE+package) -> score -> Postgres -> UI
```

| Component | Image | Role |
|---|---|---|
| `ui` | `nebari-security-posture-pack-ui` (nginx) | The only ingress target. Static SPA; proxies `/api/` to the api. |
| `api` | `nebari-security-posture-pack-api` | FastAPI on :8000. Verifies the JWT and admin group itself. Runs migrations in an init container. |
| `worker` | `nebari-security-posture-pack-worker` | One replica. Inventory, mirroring, scanning, scheduling. PVC at `/cache`. |
| `trivy` | `aquasec/trivy:0.75.0` | `trivy server` with its DB on a PVC. |
| `clair` | `quay.io/projectquay/clair:4.9.0` | Combo mode on Postgres database `clair`. |
| `postgres` | `postgres:16-alpine` | StatefulSet with databases `posture` and `clair` (or bring your own). |

### Scanners

* **Trivy**: server mode in-cluster; the worker is a thin client.
* **Grype**: runs inside the worker. Its DB lives on the worker PVC and is
  refreshed on the worker's schedule (`grype db update`, about every 12h).
* **Clair**: indexer, matcher and notifier in one process. Its updaters keep its
  own vulnerability data current.

Before scanning, the worker copies each digest into an in-cluster registry
(`scanner.mirror`, on by default). That way all three scanners see identical
bytes, upstream registries (Docker Hub rate limits) are pulled once per
digest, and Clair has one reachable registry to work against. If the mirror
step fails, the worker scans the original reference and records a warning.

### Scoring

Findings from the three scanners are merged per `(CVE, package)`. Each finding
is weighted by its severity, by how many scanners agree on it, and by whether
a fix exists. That gives a per-image score of `100 × exp(−penalty/40)`.
Sixteen configuration checks (privileged, host namespaces, run-as-root,
missing limits, mutable tags, seccomp, …) produce a posture score per workload.
The cluster score is `0.7 × vulnerability + 0.3 × posture`, weighted by
container count. Grades: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50. For the full
rules, see [docs/SCORING.md](docs/SCORING.md).

## Admin-only gating

There are three independent layers, all driven by `adminGroups` (default
`["admin"]`). A leading `/` on group names is ignored, because NIC's realm
mapper emits `/admin` and grace's operator mapper emits `admin`.

| # | Layer | Where it is enforced | Values |
|---|---|---|---|
| 1 | NebariApp `auth.groups` | Envoy Gateway, by the operator's SecurityPolicy. **Grace's operator build enforces it.** Upstream `nebari-operator` alpha.20 only uses it for landing-page visibility. | `nebariapp.auth.groups` (defaults to `adminGroups`) |
| 2 | Chart-rendered `SecurityPolicy` | Envoy Gateway: OIDC + JWT from the `NebariIdToken` cookie or a Bearer header, `authorization.defaultAction: Deny`, allow on the `groups` claim | `adminGate.securityPolicy.enabled` (default `false`) |
| 3 | API JWT verification | In the API: signature against JWKS, `exp`, `iss`, then the admin group (403 otherwise) | `auth.*`, always on unless `auth.mode=disabled` |

Which ones to use:

* **Grace** (operator with group enforcement): layers 1 and 3. This is the
  default in `deploy/grace/values.yaml`.
* **Upstream operator (alpha.20 or earlier)**: set
  `adminGate.securityPolicy.enabled=true` to use layers 2 and 3. The chart then
  renders the NebariApp with `auth.enforceAtGateway: false` and
  `forwardAccessToken: false` automatically, so the operator does not attach a
  second policy to the same HTTPRoute. It still provisions the Keycloak client
  (`provisionClient: true`), and the chart's policy reuses that client's
  Secret `<fullname>-oidc-client`. Set `adminGate.securityPolicy.externalIssuer`
  and `internalIssuer` for your cluster. On Envoy Gateway ≥ 1.5 you can also
  turn on `endSessionEndpoint` and `passThroughAuthHeader`.
* Layer 3 is always on. Even if a gateway policy is misconfigured, the API
  refuses non-admin tokens. `auth.issuers` **must** list the realm issuer(s),
  or every request is rejected.

## Install

Prerequisites: a Nebari cluster with `nebari-operator`, Envoy Gateway and
Keycloak. The namespace must carry `nebari.dev/managed=true`, or the operator
silently ignores the NebariApp.

```bash
kubectl create namespace security-posture
kubectl label namespace security-posture nebari.dev/managed=true

helm dependency build chart
helm upgrade --install security-posture ./chart -n security-posture \
  --set nebariapp.enabled=true \
  --set nebariapp.hostname=security.example.com \
  --set 'auth.issuers={https://keycloak.example.com/auth/realms/nebari,http://keycloak-keycloakx-http.keycloak.svc.cluster.local:80/auth/realms/nebari}'
```

Without Nebari (`nebariapp.enabled=false`, the default), port-forward the
`<fullname>-ui` Service. `auth.mode=disabled` is for running the API outside
the cluster only (`AUTH_MODE=disabled POSTURE_DEV=1`); the chart refuses it.

On install and upgrade two hook Jobs run first (Argo CD: PreSync): one creates
the `<fullname>-db` (and, with the Grafana listener, `<fullname>-compat-token`)
Secret if it does not exist, the other migrates the database before new pods
start. Upgrading from 0.1.x: keep `persistence.worker`/`persistence.trivy` at
their installed sizes (PVCs cannot shrink), and if you set
`provenance.helmReleases.enabled`, also set
`provenance.helmReleases.iUnderstandClusterSecretsRead=true`.

### ArgoCD

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: security-posture
  namespace: argocd
spec:
  project: nebari-apps
  source:
    repoURL: quay.io/nebari/charts
    chart: nebari-security-posture-pack
    targetRevision: 0.1.0
    helm:
      valuesObject:
        nebariapp:
          enabled: true
          hostname: security.example.com
        auth:
          issuers:
            - https://keycloak.example.com/auth/realms/nebari
            - http://keycloak-keycloakx-http.keycloak.svc.cluster.local:80/auth/realms/nebari
        postgresql:
          # Recommended under GitOps: own the credentials (sealed-secrets,
          # external-secrets, SOPS) - keys `password` and `postgres-password`.
          # Without it the PreSync hook creates <fullname>-db once (never on
          # later syncs) and annotates it Prune=false.
          existingSecret: security-posture-db
  destination:
    server: https://kubernetes.default.svc
    namespace: security-posture
  syncPolicy:
    automated: { prune: true, selfHeal: true }
    managedNamespaceMetadata:
      labels:
        nebari.dev/managed: "true"
    syncOptions:
      - CreateNamespace=true
```

## Values

The table lists the main settings. For everything else, see the comments in
[chart/values.yaml](chart/values.yaml).

| Key | Default | Description |
|---|---|---|
| `images.{api,worker,ui}.repository/tag` | `quay.io/nebari/nebari-security-posture-pack-*` / `0.1.0` | First-party images. A `digest` overrides the tag. |
| `images.{trivy,clair,postgres}` | `0.75.0` / `4.9.0` / `16.15-alpine`, each with `digest` | Third-party images pinned by tag and digest (resolve with `skopeo inspect`, `crane digest` or `docker buildx imagetools inspect`). |
| `adminGroups` | `["admin"]` | Groups allowed in. Feeds all three gating layers. |
| `adminGate.securityPolicy.enabled` | `false` | Render the chart's own Envoy SecurityPolicy (layer 2). |
| `adminGate.securityPolicy.externalIssuer` / `internalIssuer` | grace URLs | Public issuer (the `iss` claim) and in-cluster realm URL. |
| `auth.mode` | `oidc` | `disabled` is refused by the chart (development outside the cluster only). |
| `auth.jwksUrl` | in-cluster Keycloak JWKS | Used to verify token signatures. |
| `auth.issuers` | in-cluster realm URL | Accepted `iss` values. Add the external issuer your browser tokens carry; empty = the API refuses to start. |
| `auth.clientIds` / `audiences` | `[]` (= `<namespace>-<fullname>` with `nebariapp`) | `OIDC_CLIENT_IDS` / `OIDC_AUDIENCES`: `aud` must contain, or `azp` equal, one of them. |
| `scanner.parallelism` / `timeoutSeconds` | `3` / `600` | Images scanned at once, and the timeout per scanner. |
| `scanner.grype.maxConcurrent` / `scanner.maxImageGB` | `2` / `20` | Grype processes at once; larger images are scanned last, one at a time. |
| `scanner.intervalHours` / `rescanAfterHours` | `6` / `24` | Scheduled scans are due this long after the newest finished scan started (from the DB, survives restarts); digest rescan age. |
| `scanner.excludedNamespaces` | `[]` | Namespaces skipped by inventory. |
| `scanner.{trivy,grype}.enabled` | `true` | Enable each scanner. Trivy also deploys its server. |
| `scanner.clair.enabled` | `false` | Clair (opt-in): ~8 GB database, 7.5 GiB spikes, updater egress, 0.2 % unique findings on grace. Raises confidence, not coverage. |
| `clair.postgres.dedicated` / `size` | `true` / `15Gi` | Clair's own Postgres StatefulSet; `false` keeps its database on the main Postgres. |
| `scanner.mirror.enabled/registry/insecure/rewrite` | on, in-cluster registry | Mirror-then-scan. |
| `scanner.mirror.mode` / `imageCacheMaxBytes` | `""` (registry with Clair, else local) / `8Gi` | Mirror into the registry, a local OCI layout cache on the worker PVC, or off. |
| `scanner.events.enabled` / `debounceSeconds` | `true` / `300` | Targeted scans of new digests from a pod watcher; at most one event scan per `debounceSeconds` across namespaces, never while a full scan is queued or running (`EVENT_SCANS_DEBOUNCE_SECONDS`). |
| `scanner.events.minPodAgeSeconds` | `120` | Pods younger than this are held, and dropped when deleted first, so short-lived verify pods never trigger a scan (`EVENT_SCANS_MIN_POD_AGE_SECONDS`). |
| `scanner.events.includeJobs` | `false` | Pods owned by Jobs / CronJobs (backups, one-off jobs) trigger event scans too (`EVENT_SCANS_INCLUDE_JOBS`). |
| `scanner.scap.enabled` | `false` | SCAP scanner (DESIGN §14): `<fullname>-scap-worker` evaluates the OS / product STIGs inside each image with OpenSCAP. Root in its container with a minimal capability set: the pack's one privilege exception ([docs/CONTROLS.md](docs/CONTROLS.md)). Settings `scanners.scap` toggles it at runtime. |
| `scanner.scap.preferDisa` / `timeoutSeconds` / `maxRootfsGB` | `true` / `900` / `10` | Evaluate a DISA SCAP benchmark instead of the SSG profile for the same OS when both exist; per-image time budget; uncompressed rootfs cap. |
| `scanner.scap.parallelism` | `3` | Images the scap-worker evaluates concurrently (`SCAP_PARALLELISM`; oscap is single-threaded, ~1.1 GiB each); capped by `scapWorker.resources.limits.memory` at `(limit - 384Mi) / 1152Mi`. |
| `scanner.scap.finalizeWaitSeconds` | `0` | How long the privileged worker waits for a scan's SCAP stage before the posture snapshot. `0`: not at all; the scan finishes with `scapPending` ("STIG evaluation in progress (n/m)"), auto-reports and the controls run are deferred, and when the stage completes the scores are re-aggregated and the deferred stages run. |
| `scanner.scap.content.sources[]` | `[]` (= pinned SSG 0.1.82) | `{name, kind: ssg\|disa\|custom, url, sha256, include[]}`; fetched to `persistence.scapContent`, verified by sha256 before unpacking, refreshed every `content.refreshHours` (24). |
| `scanner.scap.content.offline` | `false` | Air-gapped: never fetch, index the datastreams copied to the content volume (`<volume>/local/`). |
| `scanner.scap.disa.urls[]` | `[]` | DISA `U_*_STIG_SCAP_1-3_Benchmark.zip` (or manual STIG zips) as `{url, sha256, name?, include?}`. |
| `scanner.scap.embedded` | `false` | Run the stage in the scan worker instead (dev only; non-root, so results are flagged `rootfsFidelity: degraded`). |
| `scanner.scap.imageCacheMaxBytes` | `8Gi` | scap-worker's own OCI layout cache on `persistence.scapWork`. |
| `scapWorker.resources` / `containerSecurityContext` | 250m/512Mi-3/4Gi, root + `CHOWN FOWNER DAC_OVERRIDE FSETID SETFCAP SYS_CHROOT` | Measured peak ~1.1 GiB on a RHEL 9 STIG evaluation. |
| `scanner.rawMaxGzBytes` | `null` (4Mi) | `RAW_MAX_GZ_BYTES`: raw scanner JSON kept per image scan (gzip, bytes or quantity); larger output keeps a summary only. |
| `registryAuth.existingSecret` | `""` | dockerconfigjson Secret mounted into the workers for private registries. |
| `provenance.helmReleases.enabled` / `iUnderstandClusterSecretsRead` | `false` / `false` | Helm release discovery needs get/list on every Secret (bound to `<fullname>-controls` only); both must be true. |
| `provenance.cosign.lockTrustSettings` | `true` | Cosign trust anchors only from values; the UI cannot change them. |
| `provenance.compat.internalService.*` | off | Grafana compat listener: bearer token from `<fullname>-compat-token`, NetworkPolicy for `grafanaPodSelector` pods in `allowedNamespaces`; needs `networkPolicy.enabled` unless `allowAnonymousNetwork`. |
| `controlsEngine.keycloak.viewClient.{clientId,existingSecret}` | `""` | Dedicated view-only Keycloak client; when set the admin Secret is neither granted nor read. |
| `worker.splitPrivileged` | `true` | Scan worker (`<fullname>-scanner`, no Secrets) and privileged worker (`<fullname>-controls`) as separate Deployments. |
| `worker.resources` / `worker.privileged.resources` | 500m/4Gi-3/7Gi, 100m/384Mi-1/1.5Gi | Scan worker sized for two concurrent grype processes. |
| `reportWorker.enabled` / `timeoutSeconds` | `true` / `1200` | Report generation off the api, one report at a time, child process per report. |
| `reports.retention.perType` / `maxTotalBytes` | `20` / `2Gi` | Report retention. |
| `reports.leaseSeconds` / `maxAttempts` | `null` (120) / `null` (2) | `REPORT_LEASE_SECONDS` / `REPORT_MAX_ATTEMPTS`: a report whose worker died is requeued after the lease, failed after `maxAttempts` expired leases. |
| `history.retainScans` | `30` | Scans whose per-scan history rows are kept. |
| `api.resources` / `trivy.resources` / `postgresql.resources` / `clair.resources` | 100m/384Mi-1/1Gi, 100m/256Mi-1/1.5Gi, 250m/512Mi-1/1.5Gi, 250m/1.5Gi-2/8Gi | Measured on grace (architecture review §2). |
| `postgresql.enabled` / `existingSecret` | `true` / `""` | Bundled Postgres. `<fullname>-db` is created once by a hook Job; prefer `existingSecret` under GitOps. |
| `postgresql.config` | `shared_buffers` 384MB, `work_mem` 8MB, ... | postgresql.conf settings (ConfigMap, applied as `-c`). |
| `postgresql.backup.enabled/schedule/retention/size` | `true` / `17 3 * * *` / `7` / `5Gi` | Nightly `pg_dump -Fc` of the posture database to PVC `<fullname>-backup`. |
| `hooks.migrate.enabled` | `true` | pre-upgrade migration Job (advisory lock). |
| `externalDatabase.*` | | `host`, `port`, `user`, `database`, `clairDatabase`, `sslmode`, `existingSecret`, `passwordKey`. |
| `database.driver` | `postgresql+asyncpg` | Scheme for `DATABASE_URL`. |
| `persistence.enabled/storageClass` | `true` / `""` | PVC sizes: `worker` 15Gi, `trivy` 3Gi, `postgres` 10Gi, `reports` 2Gi, `scapContent` 2Gi and `scapWork` 20Gi (only with `scanner.scap.enabled`). |
| `monitoring.enabled` | `false` | ServiceMonitor (api `:8000/metrics`) and PodMonitor (worker, worker-privileged, report-worker, port `metrics` `:9000/metrics`); needs the Prometheus Operator CRDs. Metrics and alerts: [docs/OPERATIONS.md](docs/OPERATIONS.md). |
| `monitoring.namespace` / `podSelector` | `monitoring` / `{}` | Prometheus namespace (and optional pod labels) admitted by the NetworkPolicy to `:8000` and `:9000`. |
| `monitoring.labels` | `{}` | Labels on the monitors and rule, matched by the Prometheus selectors (kube-prometheus-stack: `release: <release>`). |
| `monitoring.interval` / `scrapeTimeout` | `60s` / `30s` | Scrape settings. |
| `monitoring.rules.enabled` / `labels` / `runbookBaseUrl` | `false` / `{}` / `""` (chart home) | PrometheusRule with the alerts of docs/OPERATIONS.md; extra alert labels; `runbook_url` prefix. |
| `networkPolicy.enabled` | `true` | Ingress allow-lists (see below). |
| `networkPolicy.gatewayNamespaces` | `[envoy-gateway-system]` | Namespaces allowed to reach the ui. |
| `networkPolicy.uiAllowedNamespaces` | `[]` | Extra namespaces allowed to reach the ui, for example landing-page probers. |
| `networkPolicy.scapEgress.*` | on; `ports` `[443, 80]`, `allowedNamespaces` `[container-registry]` | scap-worker egress: DNS, the release Postgres, the registry namespace, `ports` to `cidrs` (default 0.0.0.0/0 minus `exceptCidrs`). No Kubernetes API. |
| `networkPolicy.workerEgress.*` | on; `ports` `[443, 80, 6443]`, `exceptCidrs` `[169.254.0.0/16]` | Worker egress allow-list: DNS, release pods, `allowedNamespaces`, `ports` to the internet. Add the API server port if it is not 443/6443 (MicroK8s: 16443). |
| `ui.containerPort` | `8080` | nginx listen port inside the pod. The Service listens on 80. |
| `nebariapp.enabled` | `false` | Render the NebariApp. |
| `nebariapp.hostname` | (required) | Public hostname. |
| `rbac.create` / `serviceAccount.create` / `serviceAccount.names.*` | `true` / `true` / `""` | One ServiceAccount per privilege level (below). |

`chart/values.schema.json` validates types and enums.

Network policies: the api accepts traffic only from the ui and the workers.
Postgres accepts traffic only from the api, the workers, the report-worker,
the migrate and backup Jobs (and Clair when it shares the server). Trivy and
Clair accept traffic only from the scan worker. The ui accepts traffic only
from the gateway namespaces. Worker egress is limited to DNS, the release's
pods, `networkPolicy.workerEgress.allowedNamespaces` and TCP
`workerEgress.ports`; the api, ui and report-worker have no egress policy.
The workers and the report-worker accept no ingress (the kubelet probes are not
subject to policies on common CNIs); with `monitoring.enabled`,
`monitoring.namespace` may reach the workers' `:9000` and the api's `:8000`
(`/metrics` has no authentication).

ServiceAccounts and RBAC:

| ServiceAccount | Pods | Access |
|---|---|---|
| `<fullname>-api` | api, ui, report-worker | none; token not mounted |
| `<fullname>-scanner` | worker (inventory, scan) | `get/list/watch` pods, namespaces, nodes, serviceaccounts, ReplicaSets, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, NetworkPolicies, NebariApps. **No Secrets.** |
| `<fullname>-controls` | worker-privileged (provenance, controls, reports) | controls engine ClusterRole (RBAC bindings, gateway, Envoy and cert-manager CRs); `get` on the one Keycloak admin Secret (unless `viewClient`); with `helmReleases` + acknowledgement, `get/list` on all Secrets |
| `<fullname>-scap` | scap-worker (`scanner.scap.enabled`) | none; token not mounted |
| `<fullname>-hooks` | hook Jobs | `create` Secrets in the release namespace; `get/patch` on `<fullname>-db` and `<fullname>-compat-token` |

## Grace quickstart

```bash
TAG=$(deploy/grace/build-push.sh | tail -n1)   # builds and pushes localhost:32000/security-posture-{api,worker,ui}:$TAG
TAG=$TAG deploy/grace/deploy.sh                # labels the namespace, then runs helm upgrade --install --wait
```

Then check the following:

1. `kubectl get nebariapp -n security-posture`: the conditions Ready,
   AuthReady and RoutingReady are true.
2. `curl -k https://security.100-89-230-107.sslip.io/healthz` returns 200.
3. An unauthenticated browser is redirected to Keycloak.
4. A non-admin user (for example alice) gets 403. An `admin` member sees the UI.

## Limitations (v0.1)

* **No imagePullSecrets discovery.** The scan worker has no Secret access.
  Provide credentials for private registries with
  `registryAuth.existingSecret`. Otherwise those images show as failed scans.
* Each worker is a single replica, and Postgres is a single instance; backups
  are nightly logical dumps (no WAL archiving / point-in-time recovery).
* The api mounts the ReadWriteOnce reports PVC (downloads), so it uses the
  `Recreate` strategy and the report-worker is pinned to its node.
* There is no SBOM storage, no policy enforcement or admission control, no
  multi-cluster support, and no notifications.
* The mirror registry is assumed to be plain HTTP (`scanner.mirror.insecure`).
* The chart-rendered SecurityPolicy targets the operator's HTTPRoute naming
  (`<fullname>-route`) and client id (`<namespace>-<fullname>`).

## License

Apache-2.0. See [LICENSE](LICENSE).
