# Control evidence engine (NIST SP 800-53 rev5)

Audience: ISSOs, ISSMs and assessors. This page explains what the Security Posture pack's
control evidence engine checks, how it turns those checks into an **evidence status** per NIST
SP 800-53 control, what it means by "inherited", how to tailor it, and what it cannot see.
Contract: DESIGN.md §13. Code: `api/src/posture/controls_engine/`. The vocabulary and the
mappings follow the compliance review in `docs/reviews/compliance-sme.md`.

> **Read this first.** The engine collects machine-verified *evidence* that specific technical
> settings are in place at the moment it runs. It does not test that a control is *effective*,
> it cannot see organizational processes, and it never says a control is satisfied: an assessor
> does. Its statuses describe evidence for SP 800-53A assessment objectives. Every status links to
> the raw evidence it was derived from so it can be re-verified. The realistic claim is:
> *machine-verified evidence for platform-provided and hybrid technical controls, plus a draft
> Customer Responsibility Matrix (CRM).*

## What it does

Nebari deploys its whole platform declaratively (Keycloak, Envoy Gateway, cert-manager, the
nebari-operator, the observability stack, Kubernetes itself). The engine:

1. ships an **OSCAL component definition** per platform component
   (`controls_engine/data/components/*.yaml`): which controls it addresses, its
   **responsibility** (`provider` = the platform does it all, `shared` = the platform supplies the
   mechanism and the program completes it, `customer`, `org` = the organization or an external
   provider), the program's residual responsibility (CRM text) and the assertions that collect
   evidence;
2. runs **39 read-only assertions** against the live cluster and records `pass`, `fail`,
   `unknown` or `not-applicable` with the raw evidence (JSON) and a one-line detail; each
   assertion names the **SP 800-53A assessment objectives** it evidences (`ac-7_obj.a`, ...);
3. takes the latest scan's **posture-check failures and open / SLA-overdue findings** as failing
   evidence against the mapped controls' objectives (`reports/data/controls.yaml`);
4. **derives one evidence status per control** for the selected baseline (see
   [Supported baselines](#supported-baselines-and-parameters)) from those inputs, and rolls it up per
   family;
5. publishes everything through the API and as OSCAL 1.1.2 documents (SSP draft, component
   definition, assessment-results observations) and a **draft CRM** (`GET /compliance/crm`,
   report `crm`). The SSP, assessment results, POA&M and assessment summary of a scan are all
   generated from the same control evidence run and are stamped with the run and scan ids.

It runs in the worker after every completed scan, and on demand (`POST
/api/v1/compliance/assertions/run`, or **Run assertions** in the UI). Nothing is ever written to
the cluster or to Keycloak.

## The assertions

Organization-defined parameters (lockout threshold and window, password length, timeouts,
retention) come from the selected baseline's cited ODP set, overridable in
`controlsEngine.parameters` (see below).

| id | controls (800-53A objectives) | component | severity | passes when |
|---|---|---|---|---|
| `app-gateway-auth` | AC-3, IA-2 (ac-3_obj, ia-2_obj-1) | nebari-operator | critical | Each NebariApp with `auth.enabled` has a SecurityPolicy (oidc/jwt/extAuth) targeting its HTTPRoute, or `enforceAtGateway: false` plus annotation `posture.nebari.dev/in-app-auth` documenting the in-application check. |
| `app-landing-visibility` | AC-3, AC-22 (ac-3_obj, ac-22_obj.d-1) | nebari-operator | medium | For NebariApps listed on the landing page with `auth.enabled`, the reconciled `status.serviceDiscovery.visibility` is not `public` and `requiredGroups` equals `auth.groups`. |
| `cm-certificates-valid` | SC-12, SC-17 (sc-12_obj-2, sc-17_obj.a) | cert-manager | high | Every cert-manager Certificate is Ready, unexpired, and not inside the renewal window (`controlsEngine.certRenewalWindowDays`) without having been renewed. |
| `cm-issuer-ready` | SC-12, SC-17, IA-5(2) (sc-12_obj-1, sc-17_obj.a, ia-5.2_obj.b.1) | cert-manager | high | At least one ClusterIssuer exists, every ClusterIssuer reports Ready, and every ClusterIssuer is on the approved-CA allowlist (`controlsEngine.approvedIssuers`): issuers that chain to DoD PKI, an ECA or the organization's approved CA. A `selfSigned` issuer is never approved by default, and an empty allowlist fails (SC-17 needs an approved CA; compliance review M4/M5). |
| `gw-http-redirect` | SC-8, SC-23 (sc-8_obj, sc-23_obj) | envoy-gateway | high | Every HTTPRoute attached to an HTTP (port 80) listener redirects all rules to `https`. |
| `gw-https-listener` | SC-8, SC-23 (sc-8_obj, sc-23_obj) | envoy-gateway | high | Every Gateway has a programmed HTTPS/TLS listener in Terminate mode with a certificate. |
| `gw-tls-min-version` | SC-8(1) (sc-8.1_obj) | envoy-gateway | high | ClientTrafficPolicy `tls.minVersion` >= 1.2 for every Gateway; without a policy the Envoy Gateway default (1.2) must be confirmed by a live handshake probe (TLS 1.1 refused). An unconfirmed default (probe disabled or inconclusive) is `unknown`, never a pass. |
| `k8s-api-audit-logging` | AU-2, AU-12 (au-2_obj.c-2, au-12_obj.a, au-12_obj.c) | kubernetes | high | A visible kube-apiserver pod runs with `--audit-policy-file` and a log or webhook backend. Managed / snap / systemd control planes do not expose their flags: the result is `unknown`. |
| `k8s-cluster-admin-bindings` | AC-6(1), AC-6(5) (ac-6.1_obj.a, ac-6.5_obj) | kubernetes | critical | ClusterRoleBindings to `cluster-admin` have only the explicit upstream subjects (`Group:system:masters`, `Group:kubeadm:cluster-admins`) or subjects listed in `controlsEngine.adminSubjects` (`User:alice`, `Group:ops`, `ServiceAccount:ns/name`). Other `system:` users and groups are not trusted by prefix. |
| `k8s-default-deny-egress` | SC-7(5) (sc-7.5_obj-1) | kubernetes | medium | Every non-system namespace with pods has a NetworkPolicy selecting all pods for Egress (SC-7(5) is deny by default for outbound traffic as well). |
| `k8s-default-deny-ingress` | SC-7, SC-7(5) (sc-7_obj.a-4, sc-7.5_obj-1, sc-7.5_obj-2) | kubernetes | high | Every non-system namespace with pods has a NetworkPolicy selecting all pods (`podSelector: {}`) for Ingress, so traffic not explicitly allowed is denied. |
| `k8s-default-sa-automount` | AC-6, CM-7 (ac-6_obj, cm-7_obj.a) | kubernetes | medium | The `default` ServiceAccount of every non-system namespace sets `automountServiceAccountToken: false`. |
| `k8s-no-anonymous-access` | AC-14 (ac-14_obj.a) | kubernetes | critical | No (Cluster)RoleBinding grants a role to `system:anonymous` or `system:unauthenticated`, except upstream public discovery roles (`system:public-info-viewer`). |
| `k8s-pod-security-admission` | CM-6, CM-7 (cm-6_obj.b, cm-7_obj.a) | kubernetes | high | Every non-system namespace carries `pod-security.kubernetes.io/enforce` = baseline or restricted. |
| `k8s-supported-version` | SA-22, SI-2 (sa-22_obj.a, si-2_obj.c-1) | kubernetes | high | API server and every kubelet run a Kubernetes minor version before its upstream end-of-life date. |
| `k8s-workload-least-privilege` | AC-6, CM-7 (ac-6_obj, cm-7_obj.a) | kubernetes | high | From the latest scan's posture checks: no non-system workload fails `privileged`, `host-namespaces`, `host-path`, `added-capabilities` or `privilege-escalation`. |
| `kc-admin-events` | AU-2, AU-3, AU-12 (au-2_obj.c-2, au-3_obj, au-12_obj.c) | keycloak | medium | Events config: `adminEventsEnabled` and `adminEventsDetailsEnabled`. |
| `kc-admin-mfa` | IA-2(1) (ia-2.1_obj) | keycloak | critical | The realm's browser flow *requires* a second factor (OTP, WebAuthn or X.509) for every user or, through a role condition, for administrators; a flow that only asks users who configured OTP is optional MFA and fails. Admin-group members without an enrolled second factor are listed (Keycloak forces enrolment on their next login when the step is required). |
| `kc-admin-role-allowlist` | AC-6(5) (ac-6.5_obj) | keycloak | high | Users holding the realm `admin` role (directly or through a group) are all in `controlsEngine.adminSubjects`. |
| `kc-brute-force-protection` | AC-7 (ac-7_obj.a, ac-7_obj.b) | keycloak | high | Realm `bruteForceProtected` is on and every AC-7 ODP holds: `failureFactor` <= the maximum consecutive failures; failures are counted over at least the window (`maxDeltaTimeSeconds` >= `lockoutWindowSeconds`, the "15 minutes"); the lockout lasts at least `minLockoutSeconds` (`waitIncrementSeconds` and `maxFailureWaitSeconds`) or is permanent until an administrator releases it (`permanentLockout`, required when `requireAdminRelease`, e.g. DoD). |
| `kc-login-events` | AU-12, AU-11 (au-12_obj.a, au-11_obj) | keycloak | medium | Events config: `eventsEnabled` with an expiration (stored-event retention), and the stored event types include successful and failed logins and logouts (`enabledEventTypes` empty = all). |
| `kc-mfa-all-users` | IA-2(2) (ia-2.2_obj) | keycloak | high | The realm's browser flow requires a second factor for every user (IA-2(2), non-privileged accounts): a REQUIRED OTP / WebAuthn / X.509 step not limited by a role or "user configured" condition. |
| `kc-password-policy` | IA-5(1) (ia-5.1_obj.a, ia-5.1_obj.b, ia-5.1_obj.h) | keycloak | high | Realm `passwordPolicy` sets `length` >= the organization-defined minimum (15 for the DoD profile) and a compromised / common password blocklist (`passwordBlacklist`). SP 800-53 rev5 IA-5(1) replaced composition rules with a blocklist and long passphrases, so complexity rules alone never pass (compliance review M4/M5). |
| `kc-remember-me-disabled` | AC-12 (ac-12_obj) | keycloak | low | Realm `rememberMe` is false (it would keep sessions alive across browser restarts). |
| `kc-self-registration-disabled` | AC-2 (ac-2_obj.e, ac-2_obj.f-1) | keycloak | high | Realm `registrationAllowed` is false: accounts exist only when an administrator creates them. |
| `kc-session-timeouts` | AC-12, SC-10 (ac-12_obj, sc-10_obj) | keycloak | medium | `ssoSessionIdleTimeout` and `ssoSessionMaxLifespan` are set and <= the policy values. |
| `kc-ssl-required` | SC-8 (sc-8_obj) | keycloak | high | Realm `sslRequired` is `external` or `all` (not `none`). |
| `kc-x509-authenticator` | IA-2(12) (ia-2.12_obj) | keycloak | medium | The realm's browser flow contains an enabled X.509 client-certificate authenticator (`auth-x509-client-username-form`), so PIV/CAC credentials are accepted and verified (IA-2(12), the DoD requirement for privileged MFA per DoDI 8520.03). |
| `log-ingest-all-namespaces` | AU-12 (au-12_obj.c) | loki | high | Every namespace with running pods has log streams in Loki within the last `controlsEngine.logWindowMinutes` (default 10) minutes (union over discovered Loki instances). |
| `log-pipeline-alerting` | AU-5 (au-5_obj.a) | loki | medium | Prometheus has at least one alerting rule for a failure of the log pipeline (Loki / Promtail / Alloy errors, dropped or rejected entries), so a stop in audit logging reaches someone (AU-5 a). |
| `log-retention` | AU-4, AU-11 (au-4_obj, au-11_obj) | loki | medium | Each Loki instance has retention enabled and keeps logs for at least `controlsEngine.parameters.minLogRetentionDays` (read from Loki `/config`). Retention disabled means Loki keeps logs only until storage runs out: an AU-4 / AU-5 risk, not AU-11 evidence, so it fails (compliance review M4/M5). |
| `mon-alert-receivers` | SI-4(5), IR-6(1) (si-4.5_obj, ir-6.1_obj) | prometheus | high | Alertmanager's loaded configuration has at least one receiver with an integration (email/slack/webhook/pagerduty/...) and Prometheus has at least one security-relevant alerting rule (authentication, intrusion, privilege, audit, runtime detection...). A receiver without security alert rules does not alert anyone about attacks (SI-4(5), compliance review M4). |
| `mon-prometheus-scraping` | SI-4, CA-7 (si-4_obj.c.1, ca-7_obj.d) | prometheus | medium | A Prometheus instance has active scrape targets that are up (`/api/v1/targets`). |
| `pack-inventory-current` | CM-8 (cm-8_obj.a.1, cm-8_obj.a.2, cm-8_obj.b) | security-posture | medium | The latest completed scan captured a complete inventory less than 2 x `scanIntervalHours` ago. |
| `pack-poam-current` | CA-5 (ca-5_obj.a) | security-posture | medium | When the latest full scan has open findings or failing checks, a POA&M report was generated from it (targeted event scans generate no reports). |
| `pack-scan-recent` | RA-5 (ra-5_obj.a-2) | security-posture | high | The latest completed full scan finished less than 2 x `scanIntervalHours` ago (targeted event / image rescans do not count). |
| `pack-scanner-db-fresh` | RA-5(2) (ra-5.2_obj) | security-posture | medium | Every enabled scanner reports a vulnerability DB updated within 72 hours. |
| `pack-sla-overdue` | SI-2 (si-2_obj.a-3, si-2_obj.c-1) | security-posture | high | Count of open consensus findings on running images past `firstSeen + SLA(severity)` is zero. |
| `reg-access-restricted` | AC-3, CM-5 (ac-3_obj, cm-5_obj-6) | container-registry | high | The registry's `/v2/` endpoint demands authentication (HTTP 401). An anonymous registry fails even when it is cluster-internal: any compromised pod could push (AC-3 / CM-5 access restrictions for change, compliance review M4). Exposure outside the cluster is reported as well. Read-only probe; nothing is pushed. |

Evidence sources: the Kubernetes API (read-only ClusterRole, see [Permissions](#permissions)),
the Keycloak admin REST API (`GET` only, including the browser authentication flow), Loki /
Prometheus (targets and alerting rules) / Alertmanager HTTP APIs, the registry's `/v2/`
endpoint, a TLS handshake to the gateway, and the pack's own database (latest scan, scanner
freshness, POA&M reports, SLA overdue counts, posture check results).

Every result is stored with `checkedAt`, `durationMs`, the detail line and the evidence JSON.
History per assertion is kept for the last 100 runs: `GET /api/v1/compliance/assertions/{id}`.
Each assertion also has a "looks compliant but isn't" regression fixture in the tests (for example
a `selfSigned` ClusterIssuer, Loki retention disabled, OTP that is only *optional* in the browser
flow, a password policy with complexity rules but no blocklist).

## Evidence status vocabulary

| status | meaning | OSCAL implementation-status |
|---|---|---|
| `passing` | every SP 800-53A objective of the control has passing evidence | `implemented` |
| `hybrid` | the platform's objectives pass; every other objective is explicitly assigned to the program / organization (shared responsibility, see the CRM) | `partial` + `export.responsibilities` |
| `partial` | some objectives have passing evidence ("n of m objectives"), others fail, are unknown, unassigned, or the component caps the evidence (e.g. TLS ciphers recorded but not graded) | `partial` |
| `failing` | evidence exists and none of it passes | `planned` when a POA&M item tracks it, otherwise `not-implemented` |
| `not-assessed` | no usable evidence: not run yet, unknown, an assertion found nothing to check, or nothing in the platform addresses the control | none |
| `org-provided-unverified` | declared as provided outside the platform (hosting facility) or, with `inheritOrganizationalControls`, an organization-level control assumed to be provided by the organization. **Never counted as implemented** | none |
| `inherited` | a named, authorized common control provider is configured for the control (`commonControlProviders`) | `implemented` via `leveraged-authorizations` + by-component `inherited` |
| `not-applicable` | tailored out by the AO-approved `controlsEngine.notApplicable` (never inferred by an assertion) | `not-applicable` |

## How a control's status is derived

One derivation, in this order:

1. tailored out (`controlsEngine.notApplicable`): `not-applicable`, with your justification;
2. listed by a configured common control provider: `inherited`;
3. otherwise the **objective evidence**: every leaf SP 800-53A objective of the control gets a
   state from the assertions and scan evidence that target it (`satisfied` when all of it passes,
   `not-satisfied` when any fails, `unknown`, `assigned` to the program when the component says
   so, `no-evidence`). Then `failing` if nothing passes and something fails, `partial` if some
   objectives pass but others fail / are unknown / have no evidence, `hybrid` if the rest is
   assigned, `passing` if all pass. A component `ceiling: partial` (with its reason) caps the
   result at `partial`;
4. assertions that returned `not-applicable` only (for example no Gateway API installed):
   `not-assessed`, because tailoring is an AO decision;
5. provided outside the platform, or organization-level with `inheritOrganizationalControls`:
   `org-provided-unverified`;
6. everything else: `not-assessed`.

Scan evidence (compliance review M3): a posture check failing on a non-system workload is
failing evidence against the objectives listed in `controls.yaml` `scanObjectives` (for example
`CM-7` objective a); open findings with a fix are failing evidence against `si-2_obj.a-3` (flaws
corrected) and SLA-overdue findings against `si-2_obj.c-1` (updates installed in time). So SI-2
is never `passing` while fixable findings are open. The inputs are stored per control and
returned as `scanEvidence` by `GET /compliance/controls`.

The family rollup (`GET /api/v1/compliance/families`) counts controls of the selected baseline per
family: `passing`, `hybrid`, `partial`, `failing`, `inherited`, `orgProvided`, `notApplicable`,
`notAssessed`; `totals.baseline` and `totals.catalog` sum the same keys. The UI tile shows
"Controls with passing evidence x/y"; hybrid and inherited are shown next to it and
organization-provided (unverified) is never counted.

## Inheritance, hybrid controls and the CRM

* **Provided by the platform** (`provider`): evidence from a platform setting supports every
  objective of the control (for example AC-7 lockout, AC-12 session termination). These become
  inheritable for a program only after the platform itself is assessed and authorized.
* **Shared / hybrid** (`shared`): the platform supplies the mechanism and evidence for some
  objectives; the program's part is written out in the component (`customer`) and the CRM. Most
  technical controls are here (AC-2, AC-3, AC-6, IA-2, IA-5(1), AU-12, CM-6, CM-7, SC-7, SI-2...).
* **Inherited from a named provider**: only controls you list under
  `controlsEngine.commonControlProviders[]` `{name, controls[], authorizationRef, dateAuthorized,
  statement}` (for example the hosting data center's CCP package in eMASS). The SSP references the
  provider's authorization (`leveraged-authorizations`) instead of re-asserting the control.
* **Organization-level controls** (policies, training, personnel, contingency, most CA/RA/PL/PM):
  `not-assessed` by default. `inheritOrganizationalControls=true` reports them
  `org-provided-unverified`, an explicitly unverified assumption that never counts.
* **Hosting facility** (PE-2/3/6/13/14) is a separate leveraged-system component; its controls are
  `org-provided-unverified` until you configure the provider.

The draft CRM (`GET /compliance/crm?baseline=`, report `crm` xlsx/csv) lists, per control of the
baseline, the responsibility, what the platform provides, what is provided outside the platform,
the program's residual responsibility, the current evidence status and objective coverage.

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
| `baseline` | `moderate` (chart `controlsEngine.baseline`) | `low`, `moderate`, `high`, `fedramp-moderate-rev5`, `cnssi-1253-mod-mod-mod`; selects the controls in scope, the ODP set, the SSP's imported profile and the POA&M control set |
| `adminSubjects` | `[]` | approved privileged accounts: Keycloak usernames allowed to hold the realm `admin` role and cluster-admin binding subjects (`User:alice`, `Group:platform-admins`, `ServiceAccount:argocd/argocd-application-controller`). Only `Group:system:masters` and `Group:kubeadm:cluster-admins` are trusted without listing |
| `approvedIssuers` | `[]` | cert-manager ClusterIssuers that chain to an approved CA (SC-17, IA-5(2)); empty = none approved, so `cm-issuer-ready` fails |
| `notApplicable` | `{}` | tailoring: `{"AC-17(2)": "no remote access to the system"}`; the justification is copied into the SSP |
| `commonControlProviders` | `[]` | named, authorized providers whose controls are inherited (see above) |
| `inheritOrganizationalControls` | `false` | report uncovered organization-level controls as `org-provided-unverified` instead of `not-assessed` |
| `organizationStatement` | generic text | SSP statement for organization-provided (unverified) controls |
| `stigAsset` | empty | `hostName`, `hostIp`, `hostFqdn`, `hostMac` for the STIG checklist ASSET (warned when blank) |
| `parameters.*` | `null` = profile value | `maxLoginFailures`, `lockoutWindowSeconds`, `minLockoutSeconds`, `requireAdminRelease` (AC-7); `minPasswordLength` (IA-5(1)); `maxSessionIdleSeconds`, `maxSessionLifespanSeconds` (AC-12, SC-10); `minLogRetentionDays` (AU-11); `certRenewalWindowDays` (SC-12); `logWindowMinutes` (AU-12 ingest window, default 10) |

Chart values (`controlsEngine.*`, environment variables `CONTROLS_*` on the api and worker):
`enabled`, `systemNamespaces` (exempt from the per-namespace checks and treated as PSA-exempt in
the STIG checklist; default the three Kubernetes system namespaces), `keycloak.{url, realm,
adminRealm, clientId, adminGroup, verifyTls, adminSecret.{name,namespace}}`, `lokiUrl`,
`prometheusUrl`, `alertmanagerUrl` (empty = discover Services), `registryUrl`, `timeoutSeconds`,
`tlsProbe`.

Documented exceptions in the cluster itself:

* A NebariApp with `auth.enforceAtGateway: false` passes `app-gateway-auth` only when it
  carries the annotation `posture.nebari.dev/in-app-auth: "<how the app authenticates>"`.
* Namespaces in `systemNamespaces` are skipped by the PodSecurity, default-deny, default
  ServiceAccount and workload least-privilege checks, and their posture failures do not count as
  scan evidence against controls.

Adding a component: drop a YAML file next to the shipped ones (`id`, `uuid`, `title`, `type`,
`description`, `implemented-requirements[{control, statement, responsibility, customer, assigned,
ceiling, ceilingReason, assertions[]}]`). Requirements without assertions are `not-assessed` until
you attach evidence.

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
`view-realm` (realm settings and the authentication flows read by the MFA assertions),
`view-users` and `view-events` only; the engine issues `GET` requests exclusively.

## Where to find the results

| API (`/api/v1`) | returns |
|---|---|
| `GET /compliance/controls?family=&status=&baseline=&includeAll=` | per control: evidence status, responsibility, provider, objectives with their state, scan evidence, components, assertions with evidence and `checkedAt`, `findingsOpen` / `checksFailed` |
| `GET /compliance/families?baseline=` | family rollup + baseline / catalog totals |
| `GET /compliance/crm?baseline=` | draft Customer Responsibility Matrix |
| `GET /compliance/assertions` | every assertion (with its objectives) and its latest result |
| `GET /compliance/assertions/{id}` | latest evidence + history |
| `POST /compliance/assertions/run` | 202, queues a run |
| `GET /compliance/runs`, `GET /compliance/runs/{id}` | run history (with the scan each run used) and per-status counts |
| `GET /compliance/catalog?family=&baseline=&q=` | the 800-53 rev5 catalog with baseline / profile membership and objective ids |

Reports (`POST /api/v1/reports`): `oscal-ssp` (json; option `baseline`), `oscal-component-definition`
(json) and `crm` (xlsx, csv). All are whole-system documents (cluster scope).

## Limitations

* **Configuration, not effectiveness.** The engine checks that Keycloak's lockout is configured,
  not that an attacker is actually locked out; that a default-deny NetworkPolicy exists, not that
  the CNI enforces it. Pair it with penetration testing and the assessor's own tests.
* **Objective coverage is by design narrow.** Most controls have objectives no platform can
  evidence (account reviews, approvals, documentation). Those stay `no-evidence` or are
  `assigned` to the program; this is why most controls are `partial` or `hybrid`.
* **API server audit logging** (AU-2, AU-12 for Kubernetes) is visible only when the API server
  runs as a pod (kubeadm). On managed control planes, MicroK8s (snap) or k3s it is `unknown`.
* **MFA** reads the browser flow alias set on the realm; direct-grant and other flows, identity
  provider redirects and step-up policies are not evaluated. For DoD, privileged MFA means PKI/CAC
  (IA-2(12)); OTP is generally not acceptable.
* **Alert rules** (SI-4(5), AU-5) are matched by rule name and labels; whether they detect the
  organization's indicators of compromise is a judgment the ISSO makes.
* **TLS** is judged from ClientTrafficPolicy `tls.minVersion` or a live probe; cipher suites are
  recorded, not graded against SP 800-52r2, and FIPS mode is not checked (SC-8(1) is capped at
  partial, SC-13 is not claimed).
* **Supported Kubernetes versions** come from an embedded upstream end-of-life table (1.27 to 1.36);
  distributions (MicroK8s, RKE2, OpenShift, EKS) have their own support windows.
* Statuses are point-in-time: an SSP generated from run N reflects that run's `checkedAt`.
* The SSP's information types, impact levels and authorization boundary are placeholders and are
  marked as a draft.

## Example: the `grace` lab cluster (2026-10-03, MODERATE)

With the original engine: 18 assertions pass, 16 fail, 1 unknown; of the 287 MODERATE controls
19 implemented, 6 partial, 63 not implemented and 199 "inherited". Notable findings: Keycloak
lockout after 30 failures, no password policy, admin without MFA, no event logging,
`sslRequired=none`; the Keycloak HTTPRoute also served on the plain-HTTP listener; no namespace
with a default-deny NetworkPolicy or (except two) a PodSecurity `enforce` label; Alertmanager
with only the `null` receiver; the registry anonymous on NodePort 32000.

Re-derived from the same evidence with the corrected engine (the new egress, MFA-flow, X.509 and
log-pipeline assertions evaluated as on grace's configuration): 2 passing (AC-6(5), RA-5(2)),
5 hybrid, 8 partial, 31 failing, 5 org-provided (unverified, the hosting PE controls), 236 not
assessed, 0 inherited. SI-2 and RA-5 are partial (open fixable findings, scanning of images only),
SC-17 and AU-11 fail (self-signed issuer, Loki retention disabled), and nothing is inherited
without a configured provider.
