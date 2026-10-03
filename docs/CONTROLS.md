# Control evidence engine (NIST SP 800-53 rev5)

Audience: ISSOs, ISSMs and assessors. This page explains what the Security Posture pack's
control evidence engine checks, how it turns those checks into a status per NIST SP 800-53
control, what "inherited" means in its output, how to tailor it, and what it cannot see.
Contract: DESIGN.md §13. Code: `api/src/posture/controls_engine/`.

> **Read this first.** The engine proves that specific technical *settings* are in place at
> the moment it runs. It does not test that a control is *effective*, it cannot see
> organizational processes, and an `implemented` status is evidence for an assessor, not a
> substitute for one. Every status links to the raw evidence it was derived from so it can
> be re-verified.

## What it does

Nebari deploys its whole platform declaratively (Keycloak, Envoy Gateway, cert-manager, the
nebari-operator, the observability stack, Kubernetes itself). Each of those components
implements a set of 800-53 controls. The engine:

1. ships an **OSCAL component definition** per platform component
   (`controls_engine/data/components/*.yaml`) stating which controls it implements and which
   live assertions prove it;
2. runs **35 read-only assertions** against the live cluster and records `pass`, `fail`,
   `unknown` or `not-applicable` with the raw evidence (JSON) and a one-line detail;
3. **derives a status per control** for the selected baseline (LOW / MODERATE / HIGH, from the
   official NIST OSCAL profiles vendored in `data/nist_800_53_rev5.json`, catalog 5.2.0) and
   rolls it up per family;
4. publishes everything through the API and as **OSCAL 1.1.2** documents: a
   `system-security-plan` (report type `oscal-ssp`) and a `component-definition`
   (`oscal-component-definition`), both validated against the official NIST schemas in tests.

It runs in the worker after every completed scan, and on demand (`POST
/api/v1/compliance/assertions/run`, or **Run assertions** in the UI). A run takes a few seconds.
Nothing is ever written to the cluster or to Keycloak.

## The assertions

Organization-defined parameters (lockout threshold, password length, timeouts, retention) come
from settings `controlsEngine.parameters`; the defaults are the FedRAMP Moderate values.

| id | controls | component | severity | passes when |
|---|---|---|---|---|
| `app-gateway-auth` | AC-3, IA-2 | nebari-operator | critical | Each NebariApp with `auth.enabled` has a SecurityPolicy (oidc/jwt/extAuth) targeting its HTTPRoute, or `enforceAtGateway: false` plus annotation `posture.nebari.dev/in-app-auth` documenting the in-application check. |
| `app-landing-visibility` | AC-3, AC-22 | nebari-operator | medium | For NebariApps listed on the landing page with `auth.enabled`, the reconciled `status.serviceDiscovery.visibility` is not `public` and `requiredGroups` equals `auth.groups`. |
| `cm-certificates-valid` | SC-12, SC-12(1) | cert-manager | high | Every cert-manager Certificate is Ready, unexpired, and not inside the renewal window (`controlsEngine.certRenewalWindowDays`) without having been renewed. |
| `cm-issuer-ready` | SC-12, SC-17 | cert-manager | high | At least one ClusterIssuer exists and every ClusterIssuer reports Ready. |
| `gw-http-redirect` | SC-8, SC-23 | envoy-gateway | high | Every HTTPRoute attached to an HTTP (port 80) listener redirects all rules to `https`. |
| `gw-https-listener` | SC-8, SC-23 | envoy-gateway | high | Every Gateway has a programmed HTTPS/TLS listener in Terminate mode with a certificate. |
| `gw-tls-min-version` | SC-8(1), SC-13 | envoy-gateway | high | ClientTrafficPolicy `tls.minVersion` >= 1.2 for every Gateway; without a policy the Envoy Gateway default (1.2) applies and is confirmed by a live handshake probe (TLS 1.1 must be refused). |
| `k8s-api-audit-logging` | AU-2, AU-12 | kubernetes | high | A visible kube-apiserver pod runs with `--audit-policy-file` and a log or webhook backend. Managed / snap / systemd control planes do not expose their flags: the result is `unknown`. |
| `k8s-cluster-admin-bindings` | AC-6(1) | kubernetes | critical | ClusterRoleBindings to `cluster-admin` have only `system:*` users/groups or subjects listed in `controlsEngine.adminSubjects` (`User:alice`, `Group:ops`, `ServiceAccount:ns/name`). |
| `k8s-default-deny-ingress` | SC-7, SC-7(5) | kubernetes | high | Every non-system namespace with pods has a NetworkPolicy selecting all pods (`podSelector: {}`) for Ingress, so traffic not explicitly allowed is denied. |
| `k8s-default-sa-automount` | AC-6(10) | kubernetes | medium | The `default` ServiceAccount of every non-system namespace sets `automountServiceAccountToken: false`. |
| `k8s-no-anonymous-access` | AC-14 | kubernetes | critical | No (Cluster)RoleBinding grants a role to `system:anonymous` or `system:unauthenticated`, except upstream public discovery roles (`system:public-info-viewer`). |
| `k8s-pod-security-admission` | CM-6, CM-7 | kubernetes | high | Every non-system namespace carries `pod-security.kubernetes.io/enforce` = baseline or restricted. |
| `k8s-supported-version` | SI-2 | kubernetes | high | API server and every kubelet run a Kubernetes minor version before its upstream end-of-life date. |
| `k8s-workload-least-privilege` | AC-6, CM-7 | kubernetes | high | From the latest scan's posture checks: no non-system workload fails `privileged`, `host-namespaces`, `host-path`, `added-capabilities` or `privilege-escalation`. |
| `kc-admin-events` | AU-2, AU-3, AU-12 | keycloak | medium | Events config: `adminEventsEnabled` and `adminEventsDetailsEnabled`. |
| `kc-admin-mfa` | IA-2(1) | keycloak | critical | Every member of the admin group has an OTP or WebAuthn credential (or the realm's browser flow requires OTP for everyone). |
| `kc-admin-role-allowlist` | AC-6(5) | keycloak | high | Users holding the realm `admin` role (directly or through a group) are all in `controlsEngine.adminSubjects`. |
| `kc-brute-force-protection` | AC-7 | keycloak | high | Realm `bruteForceProtected` is on and `failureFactor` <= the organization-defined maximum. |
| `kc-login-events` | AU-2, AU-12 | keycloak | medium | Events config: `eventsEnabled` with an expiration (stored-event retention). |
| `kc-password-policy` | IA-5(1) | keycloak | high | Realm `passwordPolicy` sets `length` >= the minimum and at least one complexity rule. |
| `kc-remember-me-disabled` | AC-12 | keycloak | low | Realm `rememberMe` is false (it would keep sessions alive across browser restarts). |
| `kc-self-registration-disabled` | AC-2 | keycloak | high | Realm `registrationAllowed` is false: accounts exist only when an administrator creates them. |
| `kc-session-timeouts` | AC-11, AC-12 | keycloak | medium | `ssoSessionIdleTimeout` and `ssoSessionMaxLifespan` are set and <= the policy values. |
| `kc-ssl-required` | SC-8 | keycloak | high | Realm `sslRequired` is `external` or `all` (not `none`). |
| `log-ingest-all-namespaces` | AU-2, AU-6, AU-12 | loki | high | Every namespace with running pods has log streams in Loki within the last `controlsEngine.logWindowMinutes` (default 10) minutes (union over discovered Loki instances). |
| `log-retention` | AU-4, AU-11 | loki | medium | Each Loki instance either deletes nothing (retention disabled: bounded only by storage) or keeps logs for at least `controlsEngine.minLogRetentionDays` (read from Loki `/config`). |
| `mon-alert-receivers` | SI-4(5), IR-6 | prometheus | high | Alertmanager's loaded configuration has at least one receiver with an integration (email/slack/webhook/pagerduty/...), i.e. alerts reach a person. |
| `mon-prometheus-scraping` | AU-6, SI-4 | prometheus | medium | A Prometheus instance has active scrape targets that are up (`/api/v1/targets`). |
| `pack-inventory-current` | CM-8 | security-posture | medium | The latest completed scan captured a complete inventory less than 2 x `scanIntervalHours` ago. |
| `pack-poam-current` | CA-5 | security-posture | medium | When the latest scan has open findings or failing checks, a POA&M report was generated from it. |
| `pack-scan-recent` | RA-5, RA-5(2), CA-7 | security-posture | high | The latest completed scan finished less than 2 x `scanIntervalHours` ago. |
| `pack-scanner-db-fresh` | RA-5(2), SI-5 | security-posture | medium | Every enabled scanner reports a vulnerability DB updated within 72 hours. |
| `pack-sla-overdue` | SI-2 | security-posture | high | Count of open consensus findings on running images past `firstSeen + SLA(severity)` is zero. |
| `reg-access-restricted` | CM-14, SR-4 | container-registry | high | The registry's `/v2/` endpoint demands authentication (401), or it is reachable only inside the cluster: its Service is ClusterIP (no NodePort/LoadBalancer/externalIPs) and no HTTPRoute exposes it through the gateway. Read-only probe; nothing is pushed. |

Evidence sources: the Kubernetes API (read-only ClusterRole, see [Permissions](#permissions)),
the Keycloak admin REST API (`GET` only), Loki / Prometheus / Alertmanager HTTP APIs, the
registry's `/v2/` endpoint, a TLS handshake to the gateway, and the pack's own database (latest
scan, scanner freshness, POA&M reports, SLA overdue counts, posture check results).

Every result is stored with `checkedAt`, `durationMs`, the detail line and the evidence JSON
(for example the realm's `failureFactor`, the list of namespaces without a default-deny
NetworkPolicy, the Alertmanager receivers, the negotiated TLS version). History per assertion is
kept for the last 100 runs: `GET /api/v1/compliance/assertions/{id}`.

## How a control's status is derived

Each control in scope (every control of the selected baseline, plus any other control a
component or assertion addresses) gets exactly one status. Assertions map to a control both
through their own `controls` list and through the component definitions.

| # | condition | status |
|---|---|---|
| 1 | control is tailored out (`controlsEngine.notApplicable`) | `not-applicable` (with your justification) |
| 2 | it has assertions but the engine has not run yet | `unknown` |
| 3 | all evaluated assertions pass | `implemented` |
| 3 | some pass, some fail or could not be evaluated | `partial` |
| 3 | none pass and at least one fails | `not-implemented` |
| 3 | every assertion could not be evaluated | `unknown` |
| 4 | every assertion returned `not-applicable` (e.g. no Gateway API installed) | `not-applicable` |
| 5 | a component declares it `inherited: true` (e.g. PE-3 physical access from the hosting facility) | `inherited` |
| 6 | NIST marks it organization-level (`implementation-level: organization`) and `inheritOrganizationalControls` is on | `inherited` (common control) |
| 7 | a component declares it without an assertion (custom components only) | `unknown` (manual evidence required) |
| 8 | nothing in the platform addresses it | `not-implemented` |

`not-applicable` assertion results are ignored when other assertions of the same control were
evaluated. An assertion is `unknown` when its evidence source is missing or unreachable (RBAC
forbids it, Keycloak credentials are wrong, Loki is down, it timed out after
`controlsEngine.timeoutSeconds`). A run never fails because of one assertion.

The family rollup (`GET /api/v1/compliance/families`) counts controls of the selected baseline
per family (`items`): `implemented`, `partial`, `notImplemented`, `inherited`, `notApplicable`,
`unknown`. `totals.baseline` (with `name`) sums the same baseline controls; `totals.catalog` counts
every control `GET /compliance/controls` lists by default (the baseline plus assertion-covered and
scan-evidence controls outside it, e.g. 287 vs 292 for MODERATE). The UI tiles use the baseline
numbers and show the catalog numbers in a tooltip.

In the OSCAL SSP each control becomes an `implemented-requirement` with a prop
`implementation-status` (the status above), one `by-component` per component that implements it
(OSCAL `implementation-status`: implemented → `implemented`, partial → `partial`, not-implemented
→ `planned`, inherited → `implemented` + prop `control-origination: inherited`, not-applicable →
`not-applicable`; unknown has no OSCAL state), and `links` (rel `evidence`) to back-matter
resources that embed each assertion's evidence JSON (base64) and point at the API.

## Inherited vs implemented

* **Implemented by the platform**: the control is satisfied by a platform setting this engine
  checks (Keycloak brute-force lockout for AC-7, default-deny NetworkPolicies for SC-7(5) ...).
  Its status comes from the assertions, never from a declaration.
* **Inherited from the hosting environment**: declared `inherited: true` in a component
  definition. Shipped examples: PE-2, PE-3, PE-6, PE-13, PE-14 (physical and environmental
  protection of the nodes, provided by the data center or cloud provider). The statement text is
  in the SSP. Replace or extend it with your provider's leveraged authorization.
* **Inherited from the organization (common controls)**: about 200 MODERATE controls are, per
  NIST, organization-level: policies and procedures (`-1` controls), training (AT), personnel
  security (PS), contingency planning (CP), planning (PL) and so on. No software can implement
  them. While `inheritOrganizationalControls` is on (default), those that no assertion covers are
  reported `inherited`, with the text of settings `controlsEngine.organizationStatement` in the
  SSP. **This is an assumption that your organization provides them as common controls.** Turn
  the setting off to report them `not-implemented` until you document them.
* **Not implemented / system-specific**: system-level controls that no platform component
  addresses (for example SC-28 protection of information at rest, SI-10 input validation, IA-8
  non-organizational users). The system owner must implement and document them.

## Supported baselines and parameters

Stated plainly (compliance review M7):

| `controlsEngine.baseline` | Control list | Fidelity |
|---|---|---|
| `low`, `moderate`, `high` | NIST SP 800-53B baselines (official NIST OSCAL profiles, catalog 5.2.0) | Exact |
| `fedramp-moderate-rev5` | FedRAMP Rev5 Moderate (323 controls) | Exact control list; re-verify against the FedRAMP OSCAL profile |
| `cnssi-1253-mod-mod-mod` | NIST MODERATE + the controls DISA's Kubernetes STIG / Container Platform SRG CCIs link to | **Approximation**, not the CNSSI 1253 tables (no overlays). Replace with your eMASS control set |

DoD RMF programs use CNSSI 1253 baselines with overlays; FedRAMP programs use the FedRAMP
baselines. NIST LOW / MODERATE / HIGH alone always need DoD or FedRAMP tailoring.

Each baseline has an organization-defined parameter (ODP) set with a cited source per value
(`controls_engine/data/profiles/*.json`, provenance in `controls_engine/data/README.md`). The
NIST baselines borrow the FedRAMP Rev5 values because SP 800-53B defines none. A value set in
`controlsEngine.parameters` overrides the profile; unset (`null`) uses it.

| Parameter | NIST / FedRAMP Rev5 | DoD (CNSSI approximation) |
|---|---|---|
| `maxLoginFailures` / `lockoutWindowSeconds` (AC-7 a) | 3 in 900 s | 3 in 900 s (SRG-APP-000065) |
| `minLockoutSeconds` / `requireAdminRelease` (AC-7 b) | 1800 s | administrator release (SRG-APP-000345) |
| `maxSessionIdleSeconds` (AC-11, AC-12, SC-10) | 900 | 900 (SRG-APP-000190) |
| `minPasswordLength` (IA-5(1)) | 15 (SP 800-63B-4) | 15 (SRG-APP-000164) |
| `minLogRetentionDays` (AU-11) | 365 (OMB M-21-31) | 365 (CNSSI 1253; 5 years for SAMI) |

## Tailoring

Settings (`PUT /api/v1/settings`, UI **Settings**), key `controlsEngine`:

| setting | default | meaning |
|---|---|---|
| `baseline` | `moderate` (chart `controlsEngine.baseline`) | `low`, `moderate` or `high`; selects the controls in scope and the SSP's imported profile |
| `adminSubjects` | `[]` (chart `controlsEngine.adminSubjectsAllowlist`) | approved privileged accounts: Keycloak usernames allowed to hold the realm `admin` role (`alice` or `keycloak:alice`), and cluster-admin binding subjects (`User:alice`, `Group:platform-admins`, `ServiceAccount:argocd/argocd-application-controller`). `system:*` users and groups are always allowed |
| `notApplicable` | `{}` | tailoring: `{"AC-17(2)": "no remote access to the system"}`; the justification is copied into the SSP |
| `inheritOrganizationalControls` | `true` | see [Inherited vs implemented](#inherited-vs-implemented) |
| `organizationStatement` | generic text | SSP statement for organization-provided common controls |
| `parameters.maxLoginFailures` | 3 | AC-7: maximum Keycloak `failureFactor` |
| `parameters.minPasswordLength` | 12 | IA-5(1): minimum `length(n)` in the realm password policy |
| `parameters.maxSessionIdleSeconds` | 900 | AC-11/AC-12: maximum SSO session idle timeout |
| `parameters.maxSessionLifespanSeconds` | 43200 | AC-12: maximum SSO session lifetime |
| `parameters.minLogRetentionDays` | 90 | AU-11: minimum Loki retention when retention is enabled |
| `parameters.certRenewalWindowDays` | 30 | SC-12(1): a certificate expiring sooner is a finding |
| `parameters.logWindowMinutes` | 10 | AU-12: every namespace with running pods must have logs in Loki within this window |

Chart values (`controlsEngine.*`, environment variables `CONTROLS_*` on the api and worker):
`enabled`, `systemNamespaces` (exempt from the per-namespace checks; default the three
Kubernetes system namespaces, add platform namespaces such as `metallb-system` only with a
documented reason), `keycloak.{url, realm, adminRealm, clientId, adminGroup, verifyTls,
adminSecret.{name,namespace}}`, `lokiUrl`, `prometheusUrl`, `alertmanagerUrl` (empty = discover
Services), `registryUrl` (empty = the scan mirror registry), `timeoutSeconds`, `tlsProbe`.

Documented exceptions in the cluster itself:

* A NebariApp with `auth.enforceAtGateway: false` passes `app-gateway-auth` only when it
  carries the annotation `posture.nebari.dev/in-app-auth: "<how the app authenticates>"`
  (for example JupyterHub's own OAuth login). The annotation text is the evidence.
* Namespaces in `systemNamespaces` are skipped by the PodSecurity, default-deny, default
  ServiceAccount and workload least-privilege checks.

Adding a component: drop a YAML file next to the shipped ones (same shape: `id`, `uuid`,
`title`, `type`, `description`, `implemented-requirements[{control, statement, inherited,
assertions[]}]`). It appears in the component definition and the SSP; requirements without
assertions are reported `unknown` until you attach evidence.

## Permissions

The worker's ServiceAccount gets (chart `templates/rbac.yaml`, block `controls-engine`,
rendered only with `controlsEngine.enabled`):

* a ClusterRole with `get/list/watch` on namespaces, nodes, pods, services, serviceaccounts,
  networkpolicies, clusterrolebindings, rolebindings, Gateway API gateways and httproutes,
  Envoy Gateway securitypolicies and clienttrafficpolicies, cert-manager clusterissuers and
  certificates, and NebariApps;
* a Role in the Keycloak namespace with `get` on **one** Secret
  (`controlsEngine.keycloak.adminSecret`), and nothing else in that namespace.

Keycloak credentials: the Secret holds `username`/`password` (password grant against
`admin-cli`) or `client-id`/`client-secret` (client-credentials grant), optionally `realm`.
Both a **master-realm administrator** and a **realm administrator** of the target realm work:
with `adminRealm` empty the engine tries the target realm first, then `master`. Least privilege
is a dedicated service-account client in the target realm with the `realm-management` roles
`view-realm`, `view-users` and `view-events` only; the engine issues `GET` requests exclusively.

## Where to find the results

| API (`/api/v1`) | returns |
|---|---|
| `GET /compliance/controls?family=&status=&baseline=&includeAll=` | per control: status, baseline, components, assertions with evidence and `checkedAt`, plus the scan evidence counts `findingsOpen` / `checksFailed` (§11) and their old status as `findingStatus` |
| `GET /compliance/families?baseline=` | family rollup + baseline / catalog totals |
| `GET /compliance/assertions` | every assertion with its latest result |
| `GET /compliance/assertions/{id}` | latest evidence + history |
| `POST /compliance/assertions/run` | 202, queues a run (the worker picks it up within seconds) |
| `GET /compliance/runs`, `GET /compliance/runs/{id}` | run history with per-status counts |
| `GET /compliance/catalog?family=&baseline=&q=` | the 800-53 rev5 catalog with baseline membership |

Reports (`POST /api/v1/reports`): `oscal-ssp` (json, option `baseline` overrides the setting)
and `oscal-component-definition` (json). Both are whole-system documents (cluster scope).

## Limitations

* **Configuration, not effectiveness.** The engine checks that Keycloak's lockout is configured,
  not that an attacker is actually locked out; that a default-deny NetworkPolicy exists, not that
  the CNI enforces it. Pair it with penetration testing and the assessor's own tests.
* **API server audit logging** (AU-2, AU-12 for Kubernetes) is visible only when the API server
  runs as a pod (kubeadm). On managed control planes, MicroK8s (snap) or k3s it is `unknown`;
  attach the control-plane configuration as manual evidence.
* **MFA** (IA-2(1)) counts enrolled OTP/WebAuthn credentials of the admin group's members; it
  does not inspect the authentication flow, so a user with an OTP credential under a flow that
  makes OTP optional still passes. Review the browser flow as well.
* **Log ingest** (AU-12) uses a time window: a namespace whose pods were silent for
  `logWindowMinutes` is reported missing. Loki retention disabled (compactor
  `retention_enabled: false`) means Loki deletes nothing and the check passes; size storage
  accordingly (AU-4).
* **TLS** is judged from ClientTrafficPolicy `tls.minVersion`, or, without one, from a live
  handshake from the worker (TLS 1.1 must be refused). Cipher suites are recorded, not graded.
* **Registry** access is probed read-only (`GET /v2/`): anonymous **pull** is detected; anonymous
  **push** is inferred from the absence of authentication, never attempted.
* **Supported Kubernetes versions** come from an embedded end-of-life table (1.27 to 1.36); update
  the pack to refresh it.
* **Inheritance of organization-level controls is an assumption** (see above), and inherited
  physical controls are declarations. The SSP marks both with `control-origination: inherited`.
* Statuses are point-in-time: an SSP generated from run N reflects that run's `checkedAt`.
* The SSP's information types, impact levels and authorization boundary are placeholders; set
  them for your system before submission.

## Example: the `grace` lab cluster (2026-10-03, MODERATE)

18 assertions pass, 16 fail, 1 unknown (API server audit logging, MicroK8s). Of the 287
MODERATE controls: 19 implemented, 6 partial, 63 not implemented (15 with failing assertions,
48 not addressed by any platform component), 199 inherited, 0 unknown. Notable findings:
Keycloak lockout after 30 failures, no password policy, admin without MFA, no event logging,
`sslRequired=none`; the Keycloak HTTPRoute is also served on the plain-HTTP listener; no
namespace has a default-deny NetworkPolicy or a PodSecurity `enforce` label (except two);
Alertmanager has only the `null` receiver; the registry is anonymous on NodePort 32000.
