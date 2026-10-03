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
`<fullname>-ui` Service. Use `auth.mode=disabled` for local development only.

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
          # ArgoCD renders with `helm template`, where `lookup` returns nothing,
          # so a generated password would change on every sync. Pre-create a
          # Secret with keys `password` and `postgres-password` and name it here.
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
| `images.{trivy,clair,postgres}` | `0.75.0` / `4.9.0` / `16-alpine` | Pinned third-party images. |
| `adminGroups` | `["admin"]` | Groups allowed in. Feeds all three gating layers. |
| `adminGate.securityPolicy.enabled` | `false` | Render the chart's own Envoy SecurityPolicy (layer 2). |
| `adminGate.securityPolicy.externalIssuer` / `internalIssuer` | grace URLs | Public issuer (the `iss` claim) and in-cluster realm URL. |
| `auth.mode` | `oidc` | `disabled` turns API auth off (development only). |
| `auth.jwksUrl` | in-cluster Keycloak JWKS | Used to verify token signatures. |
| `auth.issuers` | `[]` | Accepted `iss` values. **Required** for `oidc`. |
| `scanner.parallelism` / `timeoutSeconds` | `3` / `600` | Images scanned at once, and the timeout per scanner. |
| `scanner.intervalHours` / `rescanAfterHours` | `6` / `24` | Schedule, and the age after which a digest is rescanned. |
| `scanner.excludedNamespaces` | `[]` | Namespaces skipped by inventory. |
| `scanner.{trivy,grype,clair}.enabled` | `true` | Enable each scanner. Trivy and Clair also deploy their servers. |
| `scanner.mirror.enabled/registry/insecure/rewrite` | on, in-cluster registry | Mirror-then-scan. |
| `registryAuth.existingSecret` | `""` | dockerconfigjson Secret mounted into the worker for private registries. |
| `postgresql.enabled` / `existingSecret` | `true` / `""` | Bundled Postgres. The Secret `<fullname>-db` is generated once and kept. |
| `externalDatabase.*` | | `host`, `port`, `user`, `database`, `clairDatabase`, `sslmode`, `existingSecret`, `passwordKey`. |
| `database.driver` | `postgresql+asyncpg` | Scheme for `DATABASE_URL`. |
| `persistence.enabled/storageClass` | `true` / `""` | PVC sizes: `worker` 20Gi, `trivy` 10Gi, `postgres` 10Gi. |
| `networkPolicy.enabled` | `true` | Ingress allow-lists (see below). |
| `networkPolicy.gatewayNamespaces` | `[envoy-gateway-system]` | Namespaces allowed to reach the ui. |
| `networkPolicy.uiAllowedNamespaces` | `[]` | Extra namespaces allowed to reach the ui, for example landing-page probers. |
| `ui.containerPort` | `8080` | nginx listen port inside the pod. The Service listens on 80. |
| `nebariapp.enabled` | `false` | Render the NebariApp. |
| `nebariapp.hostname` | (required) | Public hostname. |
| `rbac.create` / `serviceAccount.create` | `true` | Read-only ClusterRole for api and worker. |

Network policies: the api accepts traffic only from the ui and the worker.
Postgres accepts traffic only from the api, worker and clair. Trivy and Clair
accept traffic only from the worker. The ui accepts traffic only from the
gateway namespaces. Egress is unrestricted, because the pack needs to reach
registries, Keycloak JWKS and vulnerability feeds.

RBAC: `get/list/watch` on pods, namespaces, nodes, serviceaccounts,
ReplicaSets, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs,
NetworkPolicies and `nebariapps.reconcilers.nebari.dev`. There is **no**
access to Secrets.

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

* **No imagePullSecrets discovery.** The pack has no cluster-wide Secret
  access. Provide credentials for private registries with
  `registryAuth.existingSecret`. Otherwise those images show as failed scans.
* Under `helm template` or ArgoCD, `lookup` returns nothing. Set
  `postgresql.existingSecret` there so the database password stays stable.
* The worker is a single replica, and Postgres is a single instance with no
  backups.
* There is no SBOM storage, no policy enforcement or admission control, no
  multi-cluster support, and no notifications.
* The mirror registry is assumed to be plain HTTP (`scanner.mirror.insecure`).
* The chart-rendered SecurityPolicy targets the operator's HTTPRoute naming
  (`<fullname>-route`) and client id (`<namespace>-<fullname>`).

## License

Apache-2.0. See [LICENSE](LICENSE).
