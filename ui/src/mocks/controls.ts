/**
 * §13 control evidence engine mock: ≥25 assertions (pass / fail / unknown /
 * not-applicable) evaluated against grace-like state, and a ~60-control NIST
 * SP 800-53 rev5 catalog slice whose statuses derive from those assertions
 * exactly as DESIGN §13 specifies.
 */
import type { Assertion, AssertionStatus, ControlCoverage, ControlStatus } from '@/api/types';

const COMPONENT = {
  keycloak: 'Keycloak',
  gateway: 'Envoy Gateway + nebari-operator',
  certManager: 'cert-manager',
  kubernetes: 'Kubernetes',
  loki: 'Loki / Promtail',
  prometheus: 'Prometheus / Alertmanager',
  registry: 'Container registry',
  pack: 'Security Posture pack',
  operator: 'nebari-operator',
  org: 'Organization (inherited)',
} as const;

interface AssertionSeed {
  id: string;
  title: string;
  controls: string[];
  component: string;
  severity: 'high' | 'medium' | 'low';
  status: AssertionStatus;
  detail: string;
  evidence: Record<string, unknown>;
  /** minutes before the last run */
  agoMin?: number;
}

const ASSERTION_SEEDS: AssertionSeed[] = [
  { id: 'keycloak.brute-force-detection', title: 'Brute-force detection enabled on the nebari realm', controls: ['AC-7'], component: COMPONENT.keycloak, severity: 'high', status: 'pass', detail: 'bruteForceProtected=true, lockout after 30 failures for up to 15 min', evidence: { realm: 'nebari', bruteForceProtected: true, failureFactor: 30, waitIncrementSeconds: 60, maxFailureWaitSeconds: 900, permanentLockout: false } },
  { id: 'keycloak.password-policy', title: 'Realm password policy configured', controls: ['IA-5(1)', 'IA-5'], component: COMPONENT.keycloak, severity: 'high', status: 'pass', detail: 'length(12) and upperCase(1) and digits(1) and notUsername and passwordHistory(5)', evidence: { realm: 'nebari', passwordPolicy: 'length(12) and upperCase(1) and digits(1) and notUsername(undefined) and passwordHistory(5)' } },
  { id: 'keycloak.admin-mfa', title: 'Members of admin groups have OTP required', controls: ['IA-2(1)', 'IA-2'], component: COMPONENT.keycloak, severity: 'high', status: 'fail', detail: '2 of 4 admin members have no OTP credential or CONFIGURE_TOTP required action', evidence: { groups: ['admin'], members: 4, withOtp: ['nebari-admin', 'ops-lead'], missing: ['alice', 'bob'], requiredActionsChecked: ['CONFIGURE_TOTP'] } },
  { id: 'keycloak.session-timeouts', title: 'SSO session idle and max lifespans within policy', controls: ['AC-12', 'AC-11'], component: COMPONENT.keycloak, severity: 'medium', status: 'fail', detail: 'ssoSessionMaxLifespan 36000s exceeds policy 28800s (idle 1800s OK)', evidence: { ssoSessionIdleTimeout: 1800, ssoSessionMaxLifespan: 36000, policy: { idleMax: 1800, maxLifespan: 28800 } } },
  { id: 'keycloak.remember-me-disabled', title: 'Realm “Remember me” disabled', controls: ['AC-12'], component: COMPONENT.keycloak, severity: 'low', status: 'pass', detail: 'rememberMe=false', evidence: { realm: 'nebari', rememberMe: false } },
  { id: 'keycloak.registration-disabled', title: 'Self-registration disabled', controls: ['AC-2'], component: COMPONENT.keycloak, severity: 'medium', status: 'pass', detail: 'registrationAllowed=false', evidence: { realm: 'nebari', registrationAllowed: false, registrationEmailAsUsername: false } },
  { id: 'keycloak.event-logging', title: 'Login and admin events recorded with retention', controls: ['AU-2', 'AU-12'], component: COMPONENT.keycloak, severity: 'medium', status: 'fail', detail: 'eventsEnabled=true but adminEventsEnabled=false', evidence: { eventsEnabled: true, eventsExpiration: 604800, adminEventsEnabled: false, adminEventsDetailsEnabled: false, enabledEventTypes: ['LOGIN', 'LOGIN_ERROR', 'LOGOUT'] } },
  { id: 'keycloak.realm-admin-allowlist', title: 'No realm-admin role holders beyond the allowlist', controls: ['AC-6(5)', 'AC-2'], component: COMPONENT.keycloak, severity: 'high', status: 'pass', detail: '1 realm-admin holder, all on the allowlist', evidence: { role: 'realm-management/realm-admin', holders: ['nebari-admin'], allowlist: ['nebari-admin', 'root'] } },
  { id: 'gateway.https-redirect', title: 'HTTPS listener present and HTTP redirects to HTTPS', controls: ['SC-8', 'SC-23'], component: COMPONENT.gateway, severity: 'high', status: 'pass', detail: 'Gateway nebari-gateway: https:443 (TLS terminate), http:80 → 301 https', evidence: { gateway: 'envoy-gateway-system/nebari-gateway', listeners: [{ name: 'https', port: 443, protocol: 'HTTPS', tls: 'Terminate' }, { name: 'http', port: 80, protocol: 'HTTP', redirect: { scheme: 'https', statusCode: 301 } }] } },
  { id: 'gateway.tls-min-version', title: 'ClientTrafficPolicy enforces TLS ≥ 1.2', controls: ['SC-8(1)', 'SC-13'], component: COMPONENT.gateway, severity: 'medium', status: 'unknown', detail: 'No ClientTrafficPolicy targets the gateway; Envoy default (TLS 1.2) applies but is not asserted', evidence: { clientTrafficPolicies: [], error: 'no ClientTrafficPolicy with targetRef Gateway/nebari-gateway' } },
  { id: 'gateway.nebariapp-auth', title: 'Every auth-enabled NebariApp is protected at the gateway', controls: ['AC-3', 'IA-2'], component: COMPONENT.operator, severity: 'high', status: 'fail', detail: '8 of 9 NebariApps protected; checkmaite/checkmaite-frontend has enforceAtGateway:false without an in-app check annotation', evidence: { nebariApps: 9, protected: 8, unprotected: [{ namespace: 'checkmaite', name: 'checkmaite-frontend', enforceAtGateway: false, annotation: null }] } },
  { id: 'gateway.landing-visibility', title: 'Landing-page visibility consistent with auth groups', controls: ['AC-3'], component: COMPONENT.operator, severity: 'low', status: 'pass', detail: 'All 9 landing tiles restrict visibility to their auth.groups', evidence: { nebariApps: 9, mismatched: [] } },
  { id: 'certmanager.clusterissuer-ready', title: 'ClusterIssuer exists and is Ready', controls: ['SC-12', 'SC-17'], component: COMPONENT.certManager, severity: 'high', status: 'pass', detail: 'letsencrypt-production Ready=True', evidence: { clusterIssuers: [{ name: 'letsencrypt-production', ready: true, reason: 'ACMEAccountRegistered' }, { name: 'selfsigned', ready: true }] } },
  { id: 'certmanager.certificate-expiry', title: 'No Certificates expired or expiring within 14 days', controls: ['SC-12(1)', 'SC-12'], component: COMPONENT.certManager, severity: 'medium', status: 'pass', detail: '11 Certificates, soonest expiry in 41 days', evidence: { certificates: 11, expired: 0, expiringWithin14d: 0, soonest: { name: 'nebari-gateway-tls', namespace: 'envoy-gateway-system', notAfterDays: 41 } } },
  { id: 'k8s.pod-security-enforce', title: 'Non-system namespaces enforce Pod Security ≥ baseline', controls: ['CM-6', 'CM-7'], component: COMPONENT.kubernetes, severity: 'high', status: 'fail', detail: '4 of 9 app namespaces lack pod-security.kubernetes.io/enforce', evidence: { namespaces: 9, enforcing: { restricted: ['security-posture'], baseline: ['jupyterhub', 'keycloak', 'nebari-system', 'cert-manager'] }, missing: ['checkmaite', 'minio', 'monitoring', 'longhorn-system'] } },
  { id: 'k8s.default-deny-ingress', title: 'Default-deny ingress NetworkPolicy per app namespace', controls: ['SC-7(5)', 'SC-7'], component: COMPONENT.kubernetes, severity: 'high', status: 'fail', detail: '3 of 9 app namespaces have a default-deny ingress policy', evidence: { withDefaultDeny: ['security-posture', 'keycloak', 'nebari-system'], without: ['checkmaite', 'jupyterhub', 'minio', 'monitoring', 'cert-manager', 'longhorn-system'] } },
  { id: 'k8s.cluster-admin-bindings', title: 'No cluster-admin bindings for non-system subjects beyond allowlist', controls: ['AC-6(1)', 'AC-6'], component: COMPONENT.kubernetes, severity: 'high', status: 'pass', detail: '2 cluster-admin bindings, both system or allowlisted', evidence: { bindings: [{ name: 'cluster-admin', subjects: ['Group/system:masters'] }, { name: 'microk8s-admin', subjects: ['User/admin'] }], allowlist: ['User/admin'] } },
  { id: 'k8s.default-sa-automount', title: 'default ServiceAccounts disable token automount', controls: ['AC-6(10)', 'IA-5'], component: COMPONENT.kubernetes, severity: 'medium', status: 'fail', detail: '7 of 11 namespaces leave automountServiceAccountToken unset on default', evidence: { compliant: ['security-posture', 'keycloak', 'nebari-system', 'cert-manager'], nonCompliant: ['checkmaite', 'jupyterhub', 'minio', 'monitoring', 'longhorn-system', 'envoy-gateway-system', 'default'] } },
  { id: 'k8s.no-anonymous-binding', title: 'No RBAC bindings grant system:anonymous', controls: ['AC-14'], component: COMPONENT.kubernetes, severity: 'high', status: 'pass', detail: 'no RoleBinding/ClusterRoleBinding references system:anonymous or system:unauthenticated (beyond public-info-viewer)', evidence: { matches: [], ignored: ['system:public-info-viewer'] } },
  { id: 'k8s.supported-version', title: 'Nodes run a supported Kubernetes minor', controls: ['SI-2', 'SA-22'], component: COMPONENT.kubernetes, severity: 'medium', status: 'pass', detail: 'v1.33.4 on 1 node (supported until 2026-06-28 + patch window)', evidence: { nodes: [{ name: 'grace', kubeletVersion: 'v1.33.4', osImage: 'Ubuntu 24.04.3 LTS' }], supportedMinors: ['1.32', '1.33', '1.34'] } },
  { id: 'k8s.metrics-scraping', title: 'Prometheus scrapes kubelet and kube-state-metrics', controls: ['AU-6', 'SI-4'], component: COMPONENT.prometheus, severity: 'low', status: 'pass', detail: 'targets up: kubelet 1/1, cadvisor 1/1, kube-state-metrics 1/1', evidence: { targets: { kubelet: '1/1', cadvisor: '1/1', 'kube-state-metrics': '1/1', 'node-exporter': '1/1' } } },
  { id: 'k8s.apiserver-audit', title: 'API server audit logging enabled', controls: ['AU-2', 'AU-12', 'AU-9'], component: COMPONENT.kubernetes, severity: 'high', status: 'unknown', detail: 'API server flags are not visible from inside the cluster on MicroK8s; supply evidence manually', evidence: { error: 'kube-apiserver static pod not found; MicroK8s runs the API server as a snap service', checked: ['pods -n kube-system -l component=kube-apiserver'] } },
  { id: 'logging.loki-ingest', title: 'Loki receives logs from all namespaces within 10 minutes', controls: ['AU-2', 'AU-12', 'AU-4'], component: COMPONENT.loki, severity: 'medium', status: 'pass', detail: '11/11 namespaces seen in the last 10 min; retention 744h', evidence: { query: 'count by (namespace) (count_over_time({namespace=~".+"}[10m]))', namespacesReporting: 11, namespacesTotal: 11, retentionPeriod: '744h' } },
  { id: 'logging.alertmanager-receiver', title: 'Alertmanager routes to at least one real receiver', controls: ['SI-4(5)', 'IR-6', 'SI-4'], component: COMPONENT.prometheus, severity: 'medium', status: 'fail', detail: 'only the "null" receiver is configured', evidence: { receivers: [{ name: 'null', integrations: 0 }], route: { receiver: 'null' } } },
  { id: 'registry.not-world-writable', title: 'In-cluster registry is cluster-internal or requires auth', controls: ['CM-14', 'SR-4', 'SR-11'], component: COMPONENT.registry, severity: 'high', status: 'pass', detail: 'registry Service is ClusterIP + NodePort 32000 bound to localhost only; no Ingress/HTTPRoute', evidence: { service: 'container-registry/registry', type: 'NodePort', nodePort: 32000, externalRoutes: [], hostBinding: '127.0.0.1' } },
  { id: 'registry.legacy-ingress', title: 'No legacy Ingress controller exposes the registry', controls: ['CM-7'], component: COMPONENT.registry, severity: 'low', status: 'not-applicable', detail: 'no networking.k8s.io/v1 IngressClass installed', evidence: { ingressClasses: [] } },
  { id: 'posture.scan-recency', title: 'Vulnerability scan completed within 2× the scan interval', controls: ['RA-5(2)', 'RA-5', 'CA-7'], component: COMPONENT.pack, severity: 'high', status: 'pass', detail: 'last done scan #30 finished 2h ago (interval 6h)', evidence: { lastScanId: 30, finishedHoursAgo: 2.1, scanIntervalHours: 6, limitHours: 12 } },
  { id: 'posture.scanner-db-freshness', title: 'Scanner vulnerability databases updated within 72h', controls: ['RA-5(2)', 'SI-5'], component: COMPONENT.pack, severity: 'medium', status: 'fail', detail: 'grype DB is 98h old (trivy 5h, clair 11h)', evidence: { trivy: { ageHours: 5 }, grype: { ageHours: 98 }, clair: { ageHours: 11 }, limitHours: 72 } },
  { id: 'posture.inventory-complete', title: 'Every running container is inventoried and scored', controls: ['CM-8', 'RA-5'], component: COMPONENT.pack, severity: 'medium', status: 'pass', detail: '26/27 images scored; 1 not running (private registry auth)', evidence: { images: 27, scored: 26, unscored: ['ghcr.io/acme-internal/batch-agent:1.4.0'], runningUnscored: 0 } },
  { id: 'posture.poam-generated', title: 'POA&M generated for the latest scan', controls: ['CA-5'], component: COMPONENT.pack, severity: 'medium', status: 'pass', detail: 'grace-poam-scan30.xlsx (auto) 2h ago', evidence: { reportId: 'rpt-0006', type: 'poam', scanId: 30, format: 'xlsx' } },
  { id: 'posture.sla-overdue', title: 'No findings past their remediation SLA', controls: ['SI-2', 'SI-2(2)'], component: COMPONENT.pack, severity: 'high', status: 'fail', detail: 'findings past SLA: 3 critical, 11 high', evidence: { overdue: { critical: 3, high: 11, medium: 0, low: 0 }, slaDays: { critical: 15, high: 30, medium: 90, low: 180 } } },
  { id: 'posture.images-signed', title: 'Running images carry a verified signature', controls: ['CM-14', 'SR-4', 'SR-11'], component: COMPONENT.pack, severity: 'medium', status: 'fail', detail: '8 of 27 images signed (7 verified)', evidence: { unique: 27, signed: 8, verified: 7 } },
  { id: 'posture.provenance-coverage', title: 'Running images carry SLSA provenance', controls: ['SR-3', 'SR-4', 'SA-10'], component: COMPONENT.pack, severity: 'low', status: 'fail', detail: '7 of 27 images have a provenance attestation', evidence: { unique: 27, withProvenance: 7, predicateTypes: { 'https://slsa.dev/provenance/v1': 4, 'https://slsa.dev/provenance/v0.2': 3 } } },
];

/** [id, title, lowest baseline | null, components, inherited?] */
type CatalogSeed = [string, string, 'low' | 'moderate' | 'high' | null, string[], ('inherited' | 'not-applicable')?];

const CATALOG: CatalogSeed[] = [
  ['AC-1', 'Policy and Procedures', 'low', [COMPONENT.org], 'inherited'],
  ['AC-2', 'Account Management', 'low', [COMPONENT.keycloak]],
  ['AC-2(1)', 'Automated System Account Management', 'moderate', [COMPONENT.keycloak]],
  ['AC-3', 'Access Enforcement', 'low', [COMPONENT.gateway, COMPONENT.operator]],
  ['AC-4', 'Information Flow Enforcement', 'moderate', [COMPONENT.kubernetes]],
  ['AC-6', 'Least Privilege', 'moderate', [COMPONENT.kubernetes]],
  ['AC-6(1)', 'Authorize Access to Security Functions', 'moderate', [COMPONENT.kubernetes]],
  ['AC-6(5)', 'Privileged Accounts', 'moderate', [COMPONENT.keycloak]],
  ['AC-6(10)', 'Prohibit Non-privileged Users from Executing Privileged Functions', 'moderate', [COMPONENT.kubernetes]],
  ['AC-7', 'Unsuccessful Logon Attempts', 'low', [COMPONENT.keycloak]],
  ['AC-11', 'Device Lock', 'moderate', [COMPONENT.keycloak]],
  ['AC-12', 'Session Termination', 'moderate', [COMPONENT.keycloak]],
  ['AC-14', 'Permitted Actions Without Identification or Authentication', 'low', [COMPONENT.kubernetes]],
  ['AC-17', 'Remote Access', 'low', [COMPONENT.org], 'inherited'],
  ['AU-1', 'Policy and Procedures', 'low', [COMPONENT.org], 'inherited'],
  ['AU-2', 'Event Logging', 'low', [COMPONENT.keycloak, COMPONENT.loki, COMPONENT.kubernetes]],
  ['AU-3', 'Content of Audit Records', 'low', [COMPONENT.loki]],
  ['AU-4', 'Audit Log Storage Capacity', 'low', [COMPONENT.loki]],
  ['AU-6', 'Audit Record Review, Analysis, and Reporting', 'low', [COMPONENT.prometheus]],
  ['AU-8', 'Time Stamps', 'low', [COMPONENT.org], 'inherited'],
  ['AU-9', 'Protection of Audit Information', 'low', [COMPONENT.kubernetes]],
  ['AU-11', 'Audit Record Retention', 'low', [COMPONENT.org], 'inherited'],
  ['AU-12', 'Audit Record Generation', 'low', [COMPONENT.keycloak, COMPONENT.loki]],
  ['CA-2', 'Control Assessments', 'low', [COMPONENT.org], 'inherited'],
  ['CA-5', 'Plan of Action and Milestones', 'low', [COMPONENT.pack]],
  ['CA-7', 'Continuous Monitoring', 'low', [COMPONENT.pack]],
  ['CA-9', 'Internal System Connections', 'low', [COMPONENT.kubernetes], 'not-applicable'],
  ['CM-1', 'Policy and Procedures', 'low', [COMPONENT.org], 'inherited'],
  ['CM-2', 'Baseline Configuration', 'low', [COMPONENT.kubernetes]],
  ['CM-3', 'Configuration Change Control', 'moderate', [COMPONENT.org]],
  ['CM-6', 'Configuration Settings', 'low', [COMPONENT.kubernetes]],
  ['CM-7', 'Least Functionality', 'low', [COMPONENT.kubernetes, COMPONENT.registry]],
  ['CM-8', 'System Component Inventory', 'low', [COMPONENT.pack]],
  ['CM-11', 'User-installed Software', 'low', [COMPONENT.kubernetes], 'not-applicable'],
  ['CM-14', 'Signed Components', null, [COMPONENT.registry, COMPONENT.pack]],
  ['IA-1', 'Policy and Procedures', 'low', [COMPONENT.org], 'inherited'],
  ['IA-2', 'Identification and Authentication (Organizational Users)', 'low', [COMPONENT.keycloak, COMPONENT.gateway]],
  ['IA-2(1)', 'Multi-factor Authentication to Privileged Accounts', 'low', [COMPONENT.keycloak]],
  ['IA-2(2)', 'Multi-factor Authentication to Non-privileged Accounts', 'low', [COMPONENT.keycloak]],
  ['IA-5', 'Authenticator Management', 'low', [COMPONENT.keycloak, COMPONENT.kubernetes]],
  ['IA-5(1)', 'Password-based Authentication', 'low', [COMPONENT.keycloak]],
  ['IA-8', 'Identification and Authentication (Non-organizational Users)', 'low', [COMPONENT.org], 'inherited'],
  ['IR-4', 'Incident Handling', 'low', [COMPONENT.org], 'inherited'],
  ['IR-5', 'Incident Monitoring', 'low', [COMPONENT.org], 'inherited'],
  ['IR-6', 'Incident Reporting', 'low', [COMPONENT.prometheus]],
  ['PL-2', 'System Security and Privacy Plans', 'low', [COMPONENT.org], 'inherited'],
  ['RA-3', 'Risk Assessment', 'low', [COMPONENT.org], 'inherited'],
  ['RA-5', 'Vulnerability Monitoring and Scanning', 'low', [COMPONENT.pack]],
  ['RA-5(2)', 'Update Vulnerabilities to Be Scanned', 'low', [COMPONENT.pack]],
  ['RA-5(5)', 'Privileged Access', 'moderate', [COMPONENT.pack], 'not-applicable'],
  ['SA-8', 'Security and Privacy Engineering Principles', 'low', [COMPONENT.org], 'inherited'],
  ['SA-10', 'Developer Configuration Management', 'moderate', [COMPONENT.pack]],
  ['SA-11', 'Developer Testing and Evaluation', 'moderate', [COMPONENT.org], 'inherited'],
  ['SA-22', 'Unsupported System Components', 'low', [COMPONENT.kubernetes]],
  ['SC-5', 'Denial-of-service Protection', 'low', [COMPONENT.org], 'inherited'],
  ['SC-6', 'Resource Availability', null, [COMPONENT.kubernetes]],
  ['SC-7', 'Boundary Protection', 'low', [COMPONENT.gateway, COMPONENT.kubernetes]],
  ['SC-7(5)', 'Deny by Default — Allow by Exception', 'moderate', [COMPONENT.kubernetes]],
  ['SC-8', 'Transmission Confidentiality and Integrity', 'moderate', [COMPONENT.gateway]],
  ['SC-8(1)', 'Cryptographic Protection', 'moderate', [COMPONENT.gateway]],
  ['SC-12', 'Cryptographic Key Establishment and Management', 'low', [COMPONENT.certManager]],
  ['SC-12(1)', 'Availability', 'high', [COMPONENT.certManager]],
  ['SC-13', 'Cryptographic Protection', 'low', [COMPONENT.gateway]],
  ['SC-17', 'Public Key Infrastructure Certificates', 'moderate', [COMPONENT.certManager]],
  ['SC-23', 'Session Authenticity', 'moderate', [COMPONENT.gateway]],
  ['SC-28', 'Protection of Information at Rest', 'moderate', [COMPONENT.kubernetes]],
  ['SC-39', 'Process Isolation', 'low', [COMPONENT.org], 'inherited'],
  ['SI-2', 'Flaw Remediation', 'low', [COMPONENT.pack, COMPONENT.kubernetes]],
  ['SI-2(2)', 'Automated Flaw Remediation Status', 'moderate', [COMPONENT.pack]],
  ['SI-3', 'Malicious Code Protection', 'low', [COMPONENT.pack]],
  ['SI-4', 'System Monitoring', 'low', [COMPONENT.prometheus]],
  ['SI-4(5)', 'System-generated Alerts', 'moderate', [COMPONENT.prometheus]],
  ['SI-5', 'Security Alerts, Advisories, and Directives', 'low', [COMPONENT.pack]],
  ['SI-13', 'Predictable Failure Prevention', null, [COMPONENT.kubernetes]],
  ['SI-16', 'Memory Protection', 'moderate', [COMPONENT.kubernetes]],
  ['SR-2', 'Supply Chain Risk Management Plan', 'low', [COMPONENT.org], 'inherited'],
  ['SR-3', 'Supply Chain Controls and Processes', 'low', [COMPONENT.pack]],
  ['SR-4', 'Provenance', null, [COMPONENT.pack, COMPONENT.registry]],
  ['SR-11', 'Component Authenticity', 'low', [COMPONENT.pack, COMPONENT.registry]],
];

/** Last engine run; bumped by POST /compliance/assertions/run. */
let lastRunAt = Date.now() - 37 * 60_000;
export function setAssertionRunAt(t: number) {
  lastRunAt = t;
}
export function resetAssertionRun() {
  lastRunAt = Date.now() - 37 * 60_000;
}

export function assertions(): Assertion[] {
  return ASSERTION_SEEDS.map((a, i) => ({
    id: a.id,
    title: a.title,
    controls: a.controls,
    component: a.component,
    severity: a.severity,
    status: a.status,
    detail: a.detail,
    evidence: a.evidence,
    checkedAt: new Date(lastRunAt - (a.agoMin ?? i % 3) * 1000).toISOString(),
  }));
}

/** DESIGN §13 status derivation. */
export function deriveStatus(statuses: string[]): ControlStatus {
  const s = statuses.filter((x) => x !== 'not-applicable');
  if (!statuses.length) return 'not-implemented';
  if (!s.length) return 'not-applicable';
  const pass = s.filter((x) => x === 'pass').length;
  const fail = s.filter((x) => x === 'fail').length;
  if (pass === s.length) return 'implemented';
  if (pass > 0) return 'partial';
  if (fail > 0) return 'not-implemented';
  return 'unknown';
}

/**
 * `GET /compliance/controls` catalog. `extra` merges §11 findings/check
 * counts (from the scan) into the matching controls; findings or failed
 * checks against an otherwise passing control make it partial.
 */
export function controlCatalog(extra: Map<string, { findingsOpen: number; checksFailed: number }>): ControlCoverage[] {
  const all = assertions();
  return CATALOG.map(([control, title, baseline, components, fixed]) => {
    const mapped = all.filter((a) => a.controls.includes(control));
    const counts = extra.get(control) ?? { findingsOpen: 0, checksFailed: 0 };
    let status: ControlStatus = fixed ?? deriveStatus(mapped.map((a) => String(a.status)));
    if (!fixed && !mapped.length && counts.findingsOpen + counts.checksFailed === 0 && extra.has(control)) status = 'implemented';
    if (status === 'implemented' && counts.findingsOpen + counts.checksFailed > 0) status = 'partial';
    if (!fixed && !mapped.length && counts.findingsOpen + counts.checksFailed > 0) status = 'partial';
    return {
      control,
      title,
      family: control.split('-')[0],
      baseline,
      status,
      components,
      assertions: mapped.map(({ id, title: t, status: st, evidence, checkedAt, detail }) => ({ id, title: t, status: st, evidence, checkedAt, detail })),
      findingsOpen: counts.findingsOpen,
      checksFailed: counts.checksFailed,
    };
  });
}
