/**
 * Deterministic demo dataset for VITE_API_MOCK=1 and tests. Everything is
 * derived from a seeded PRNG so screenshots and tests are stable, while
 * timestamps are relative to "now" so relative times look fresh.
 */
import type {
  Check,
  CheckResult,
  ContainerRef,
  ControlCoverage,
  Finding,
  Grade,
  ImageDetail,
  Me,
  Namespace,
  PostureFinding,
  Report,
  ReportType,
  Scan,
  ScannerHealth,
  ScannerName,
  ScannerRun,
  ScannerRunStatus,
  Settings,
  Severity,
  SeverityCounts,
  StigRule,
  Summary,
  SupplyChainSummary,
  TrendPoint,
  Workload,
} from '@/api/types';
import { SCANNERS } from '@/api/types';
import { emptyCounts, gradeForScore, imageVulnScore, maxSeverity, SEVERITY_WEIGHT } from '@/lib/scoring';
import { clusterScore as weightedClusterScore, supplyChainScore, updateLevel } from '@/lib/supply-chain';
import { controlCatalog } from './controls';
import { helmReleases, PROVENANCE_BY_REF } from './provenance';
import { type CveSeed, GO_CVES, JAVA_CVES, NODE_CVES, OS_CVES, PY_CVES } from './cves';

// ── PRNG ─────────────────────────────────────────────────────────────────────
function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(20261002);

const sample = <T,>(xs: readonly T[], n: number): T[] => {
  const copy = [...xs];
  const out: T[] = [];
  while (out.length < n && copy.length) out.push(copy.splice(Math.floor(rand() * copy.length), 1)[0]);
  return out;
};
const hex = (n: number) => Array.from({ length: n }, () => Math.floor(rand() * 16).toString(16)).join('');

export const NOW = Date.now();
const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString();

// ── Scanner metadata ─────────────────────────────────────────────────────────
export const SCANNER_VERSIONS: Record<ScannerName, string> = { trivy: '0.75.0', grype: '0.92.2', clair: '4.9.0' };
export const SCANNER_DB_AGE_H: Record<ScannerName, number> = { trivy: 5, grype: 98, clair: 11 };

// ── Image catalogue ──────────────────────────────────────────────────────────
type Eco = 'os' | 'go' | 'py' | 'node' | 'java';
interface ImageSeed {
  ref: string;
  ns: Array<[string, string, string]>; // namespace, kind, name
  eco: Eco[];
  /** how many findings to draw */
  n: number;
  /** per-scanner forced status */
  fail?: Partial<Record<ScannerName, { status: ScannerRunStatus; error: string }>>;
  running?: boolean;
  pack?: string;
}

const IMAGE_SEEDS: ImageSeed[] = [
  { ref: 'docker.io/library/python:3.9-slim', ns: [['jupyterhub', 'Deployment', 'legacy-notebook-proxy']], eco: ['os', 'py'], n: 34, pack: 'jupyterhub' },
  { ref: 'localhost:32000/checkmaite-frontend:latest', ns: [['checkmaite', 'Deployment', 'checkmaite-frontend']], eco: ['os', 'node'], n: 22, pack: 'checkmaite', fail: { clair: { status: 'timeout', error: 'clairctl: context deadline exceeded after 600s waiting for index report' } } },
  { ref: 'quay.io/keycloak/keycloak:26.0.5', ns: [['keycloak', 'StatefulSet', 'keycloak-keycloakx']], eco: ['os', 'java'], n: 18, pack: 'keycloak' },
  { ref: 'docker.io/bitnami/postgresql:16.4.0-debian-12-r2', ns: [['keycloak', 'StatefulSet', 'keycloak-postgresql'], ['checkmaite', 'StatefulSet', 'checkmaite-db']], eco: ['os', 'go'], n: 20 },
  { ref: 'quay.io/jupyterhub/k8s-hub:4.0.0', ns: [['jupyterhub', 'Deployment', 'hub']], eco: ['os', 'py'], n: 15, pack: 'jupyterhub' },
  { ref: 'quay.io/jupyterhub/configurable-http-proxy:4.6.2', ns: [['jupyterhub', 'Deployment', 'proxy']], eco: ['os', 'node'], n: 9, pack: 'jupyterhub' },
  { ref: 'docker.io/grafana/grafana:11.3.0', ns: [['monitoring', 'Deployment', 'grafana']], eco: ['os', 'go'], n: 12, pack: 'monitoring' },
  { ref: 'docker.io/grafana/loki:3.2.0', ns: [['monitoring', 'StatefulSet', 'loki']], eco: ['go'], n: 8, pack: 'monitoring', fail: { clair: { status: 'unsupported', error: 'no package database found (distroless/scratch image)' } } },
  { ref: 'quay.io/prometheus/prometheus:v2.55.0', ns: [['monitoring', 'StatefulSet', 'prometheus-server']], eco: ['go'], n: 6, pack: 'monitoring' },
  { ref: 'quay.io/prometheus/node-exporter:v1.8.2', ns: [['monitoring', 'DaemonSet', 'node-exporter']], eco: ['go'], n: 4, pack: 'monitoring' },
  { ref: 'docker.io/calico/node:v3.28.1', ns: [['kube-system', 'DaemonSet', 'calico-node']], eco: ['os', 'go'], n: 11 },
  { ref: 'docker.io/calico/kube-controllers:v3.28.1', ns: [['kube-system', 'Deployment', 'calico-kube-controllers']], eco: ['go'], n: 5 },
  { ref: 'registry.k8s.io/coredns/coredns:v1.11.1', ns: [['kube-system', 'Deployment', 'coredns']], eco: ['go'], n: 7, fail: { clair: { status: 'unsupported', error: 'no package database found (distroless/scratch image)' } } },
  { ref: 'registry.k8s.io/pause:3.9', ns: [['kube-system', 'DaemonSet', 'calico-node'], ['jupyterhub', 'Deployment', 'hub']], eco: [], n: 0, fail: { clair: { status: 'unsupported', error: 'no package database found (distroless/scratch image)' } } },
  { ref: 'docker.io/envoyproxy/gateway:v1.2.1', ns: [['envoy-gateway-system', 'Deployment', 'envoy-gateway']], eco: ['go'], n: 6, pack: 'nebari-system' },
  { ref: 'docker.io/envoyproxy/envoy:distroless-v1.32.1', ns: [['envoy-gateway-system', 'Deployment', 'envoy-public-gateway']], eco: ['os'], n: 3, pack: 'nebari-system' },
  { ref: 'quay.io/jetstack/cert-manager-controller:v1.16.1', ns: [['cert-manager', 'Deployment', 'cert-manager']], eco: ['go'], n: 4 },
  { ref: 'quay.io/nebari/nebari-landing:0.3.1', ns: [['nebari-system', 'Deployment', 'nebari-landing']], eco: ['os', 'node'], n: 3, pack: 'nebari-system' },
  { ref: 'quay.io/nebari/nebari-operator:v0.1.0-alpha.20', ns: [['nebari-system', 'Deployment', 'nebari-operator']], eco: ['go'], n: 2, pack: 'nebari-system' },
  { ref: 'docker.io/library/redis:7.2.4', ns: [['checkmaite', 'Deployment', 'checkmaite-cache']], eco: ['os', 'go'], n: 10, pack: 'checkmaite' },
  { ref: 'docker.io/minio/minio:RELEASE.2024-10-13T13-34-11Z', ns: [['minio', 'StatefulSet', 'minio']], eco: ['go'], n: 5, fail: { grype: { status: 'error', error: 'failed to catalog: unable to read layer sha256:4f4f…: unexpected EOF' } } },
  { ref: 'docker.io/longhornio/longhorn-manager:v1.7.2', ns: [['longhorn-system', 'DaemonSet', 'longhorn-manager']], eco: ['os', 'go'], n: 14 },
  { ref: 'docker.io/aquasec/trivy:0.75.0', ns: [['security-posture', 'Deployment', 'security-posture-trivy']], eco: ['os', 'go'], n: 2, pack: 'security-posture' },
  { ref: 'quay.io/projectquay/clair:4.9.0', ns: [['security-posture', 'Deployment', 'security-posture-clair']], eco: ['os', 'go'], n: 3, pack: 'security-posture' },
  { ref: 'docker.io/library/postgres:16-alpine', ns: [['security-posture', 'StatefulSet', 'security-posture-postgres']], eco: ['os', 'go'], n: 4, pack: 'security-posture' },
  { ref: 'localhost:32000/security-posture-api:4c1e9a2', ns: [['security-posture', 'Deployment', 'security-posture-api'], ['security-posture', 'Deployment', 'security-posture-worker']], eco: ['os', 'py'], n: 1, pack: 'security-posture' },
  { ref: 'ghcr.io/acme-internal/batch-agent:1.4.0', ns: [['checkmaite', 'CronJob', 'nightly-export']], eco: ['os'], n: 0, running: false, pack: 'checkmaite', fail: {
    trivy: { status: 'error', error: 'UNAUTHORIZED: authentication required (imagePullSecrets are not supported in v0.1)' },
    grype: { status: 'error', error: 'GET https://ghcr.io/v2/acme-internal/batch-agent/manifests/1.4.0: UNAUTHORIZED' },
    clair: { status: 'error', error: 'mirror failed and original ref unreachable: 401 Unauthorized' },
  } },
];

const ECO_POOL: Record<Eco, CveSeed[]> = { os: OS_CVES, go: GO_CVES, py: PY_CVES, node: NODE_CVES, java: JAVA_CVES };
const LOWER: Record<Severity, Severity> = { critical: 'high', high: 'medium', medium: 'low', low: 'negligible', negligible: 'negligible', unknown: 'unknown' };

function controlsFor(fixable: boolean): string[] {
  return fixable ? ['RA-5', 'SI-2', 'SI-2(2)'] : ['RA-5', 'SI-2'];
}

function parseRef(ref: string) {
  const [path, tag] = ref.split(/:(?=[^/]+$)/);
  const parts = path.split('/');
  const registry = parts[0].includes('.') || parts[0].includes(':') ? parts[0] : 'docker.io';
  const repository = parts.slice(registry === parts[0] ? 1 : 0).join('/');
  return { registry, repository, tag: tag ?? null };
}

const imageId = (i: number) => `img-${String(i + 1).padStart(3, '0')}`;

function buildFindings(seed: ImageSeed, ok: ScannerName[]): Finding[] {
  const pool = seed.eco.flatMap((e) => ECO_POOL[e]);
  const chosen = sample(pool, Math.min(seed.n, pool.length));
  const findings: Finding[] = [];
  for (const [vulnId, pkg, pkgType, sev, installed, fixed, cvss, title] of chosen) {
    if (!ok.length) break;
    // which scanners flag it: most findings are agreed by all; some only by 1-2
    const r = rand();
    let flagged: ScannerName[];
    if (r < 0.62) flagged = [...ok];
    else if (r < 0.85) flagged = sample(ok, Math.max(1, ok.length - 1));
    else flagged = sample(ok, 1);
    // Clair is weak at language packages
    if (pkgType !== 'apk' && pkgType !== 'deb') flagged = flagged.filter((s) => s !== 'clair' || rand() < 0.3);
    if (!flagged.length) flagged = [ok.includes('trivy') ? 'trivy' : ok[0]];
    const perScanner: Partial<Record<ScannerName, Severity>> = {};
    for (const s of flagged) perScanner[s] = rand() < 0.18 ? LOWER[sev] : sev;
    const consensus = maxSeverity(Object.values(perScanner)) ?? sev;
    const fixable = fixed !== null;
    const firstSeenDays = Math.floor(rand() * 120);
    const sla = { critical: 15, high: 30, medium: 90, low: 180, negligible: 365, unknown: 365 }[consensus];
    findings.push({
      vulnId,
      severity: consensus,
      package: pkg,
      installedVersion: installed,
      fixedVersion: fixed,
      pkgType,
      scanners: SCANNERS.filter((s) => flagged.includes(s)),
      agreement: Math.round((flagged.length / ok.length) * 100) / 100,
      perScanner,
      cvss,
      title,
      url: vulnId.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${vulnId}` : null,
      fixable,
      controls: controlsFor(fixable),
      firstSeenAt: iso(firstSeenDays * 24 * HOUR),
      slaDueAt: iso((firstSeenDays - sla) * 24 * HOUR),
      overdue: firstSeenDays > sla,
    });
  }
  return findings.sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity] || a.vulnId.localeCompare(b.vulnId));
}

function countFindings(findings: Finding[]) {
  const counts = emptyCounts();
  const fixable = emptyCounts();
  for (const f of findings) {
    counts[f.severity] += 1;
    if (f.fixable) fixable[f.severity] += 1;
  }
  return { counts, fixable };
}

// ── Posture checks ───────────────────────────────────────────────────────────
interface CheckSeed extends Omit<Check, 'passed' | 'failed'> {
  failRate: number;
  systemFailRate?: number;
}

export const CHECK_SEEDS: CheckSeed[] = [
  { id: 'privileged', title: 'Privileged containers', severity: 'critical', category: 'Privileges', description: 'Container runs with securityContext.privileged=true, giving it full access to the host kernel and devices.', remediation: 'Remove `privileged: true`. If specific kernel capabilities are needed, grant them individually via `capabilities.add` and document why.', controls: ['AC-6', 'CM-7'], stig: { vulnId: 'V-242437', ruleId: 'SV-242437r879719_rule', cat: 'I' }, failRate: 0, systemFailRate: 0.6 },
  { id: 'host-namespaces', title: 'Host namespaces shared', severity: 'critical', category: 'Isolation', description: 'Pod sets hostPID, hostIPC or hostNetwork, breaking process/network isolation from the node.', remediation: 'Set `hostPID`, `hostIPC` and `hostNetwork` to false. Use a Service or NodePort instead of hostNetwork.', controls: ['SC-7', 'CM-7'], stig: { vulnId: 'V-242414', ruleId: 'SV-242414r879588_rule', cat: 'II' }, failRate: 0, systemFailRate: 0.5 },
  { id: 'host-path', title: 'hostPath volumes', severity: 'high', category: 'Isolation', description: 'Pod mounts a hostPath volume, exposing the node filesystem.', remediation: 'Replace hostPath with a PersistentVolumeClaim, emptyDir, ConfigMap or projected volume.', controls: ['SC-7', 'CM-7'], stig: { vulnId: 'V-242383', ruleId: 'SV-242383r879533_rule', cat: 'I' }, failRate: 0.04, systemFailRate: 0.7 },
  { id: 'run-as-root', title: 'Runs as root', severity: 'high', category: 'Privileges', description: 'Neither the container nor the pod sets runAsNonRoot: true and runAsUser is unset or 0.', remediation: 'Set `securityContext.runAsNonRoot: true` and a non-zero `runAsUser` (e.g. 65532). Rebuild the image with a USER directive if needed.', controls: ['AC-6', 'CM-7'], failRate: 0.38, systemFailRate: 0.8 },
  { id: 'privilege-escalation', title: 'Privilege escalation allowed', severity: 'high', category: 'Privileges', description: 'allowPrivilegeEscalation is not explicitly false, so setuid binaries can gain privileges.', remediation: 'Set `securityContext.allowPrivilegeEscalation: false` on every container.', controls: ['AC-6', 'CM-7'], stig: { vulnId: 'V-242436', ruleId: 'SV-242436r879718_rule', cat: 'II' }, failRate: 0.55, systemFailRate: 0.9 },
  { id: 'added-capabilities', title: 'Added Linux capabilities', severity: 'high', category: 'Privileges', description: 'Container adds Linux capabilities. NET_ADMIN / SYS_ADMIN are treated as critical.', remediation: 'Drop `capabilities.add` entries unless strictly required; prefer NET_BIND_SERVICE over NET_ADMIN.', controls: ['AC-6', 'CM-7'], failRate: 0.05, systemFailRate: 0.5 },
  { id: 'capabilities-not-dropped', title: 'Capabilities not dropped', severity: 'medium', category: 'Privileges', description: '`capabilities.drop` does not include ALL.', remediation: 'Add `capabilities: { drop: ["ALL"] }` and add back only what is needed.', controls: ['AC-6', 'CM-7'], failRate: 0.6, systemFailRate: 0.9 },
  { id: 'writable-rootfs', title: 'Writable root filesystem', severity: 'medium', category: 'Hardening', description: 'readOnlyRootFilesystem is not true.', remediation: 'Set `readOnlyRootFilesystem: true` and mount emptyDir volumes for paths that need writes (/tmp, caches).', controls: ['CM-6', 'CM-7'], failRate: 0.7, systemFailRate: 0.8 },
  { id: 'no-resource-limits', title: 'No resource limits', severity: 'medium', category: 'Resources', description: 'CPU or memory limits are unset.', remediation: 'Set `resources.limits.cpu` and `resources.limits.memory` appropriate for the workload.', controls: ['SC-6'], stig: { vulnId: 'V-242434', ruleId: 'SV-242434r879717_rule', cat: 'II' }, failRate: 0.35, systemFailRate: 0.4 },
  { id: 'no-resource-requests', title: 'No resource requests', severity: 'low', category: 'Resources', description: 'CPU or memory requests are unset.', remediation: 'Set `resources.requests` so the scheduler can place the pod correctly.', controls: ['SC-6'], failRate: 0.2, systemFailRate: 0.2 },
  { id: 'mutable-tag', title: 'Mutable image tag', severity: 'medium', category: 'Supply chain', description: 'Image tag is `latest` or missing and no digest is pinned in the spec.', remediation: 'Reference images by immutable tag and digest, e.g. `repo:1.2.3@sha256:…`.', controls: ['CM-2', 'CM-14'], failRate: 0.08, systemFailRate: 0 },
  { id: 'no-liveness-probe', title: 'No liveness probe', severity: 'low', category: 'Reliability', description: 'Long-running container has no livenessProbe.', remediation: 'Add an HTTP, TCP or exec `livenessProbe`.', controls: ['SI-13'], failRate: 0.3, systemFailRate: 0.1 },
  { id: 'no-readiness-probe', title: 'No readiness probe', severity: 'low', category: 'Reliability', description: 'Container has no readinessProbe.', remediation: 'Add a `readinessProbe` so traffic only reaches ready pods.', controls: ['SI-13'], failRate: 0.35, systemFailRate: 0.1 },
  { id: 'automount-sa-token', title: 'Default SA token automounted', severity: 'low', category: 'Identity', description: 'automountServiceAccountToken is not false and the pod uses the `default` ServiceAccount.', remediation: 'Set `automountServiceAccountToken: false` or use a dedicated ServiceAccount with least-privilege RBAC.', controls: ['AC-6(10)', 'IA-5'], stig: { vulnId: 'V-242415', ruleId: 'SV-242415r879589_rule', cat: 'I' }, failRate: 0.25, systemFailRate: 0.1 },
  { id: 'seccomp-unconfined', title: 'Seccomp unconfined', severity: 'medium', category: 'Hardening', description: 'seccompProfile type is Unconfined or unset at both pod and container level.', remediation: 'Set `securityContext.seccompProfile.type: RuntimeDefault` at the pod level.', controls: ['CM-6', 'SI-16'], stig: { vulnId: 'V-242417', ruleId: 'SV-242417r879591_rule', cat: 'II' }, failRate: 0.5, systemFailRate: 0.7 },
  { id: 'no-netpol', title: 'No NetworkPolicy', severity: 'low', category: 'Network', description: 'No NetworkPolicy in the namespace selects this pod.', remediation: 'Add a default-deny NetworkPolicy and explicit allow rules for required traffic.', controls: ['SC-7', 'AC-4'], stig: { vulnId: 'V-242410', ruleId: 'SV-242410r879584_rule', cat: 'III' }, failRate: 0.4, systemFailRate: 0.9 },
];

const POSTURE_WEIGHT: Record<Severity, number> = { critical: 10, high: 4, medium: 1, low: 0.2, negligible: 0, unknown: 0 };

// ── Build dataset ────────────────────────────────────────────────────────────
interface WorkloadAcc {
  namespace: string;
  kind: string;
  name: string;
  pack: string | null;
  containers: number;
  images: { imageId: string; ref: string }[];
  results: Map<string, CheckResult>;
}

export const images: ImageDetail[] = [];
const workloadMap = new Map<string, WorkloadAcc>();
const checkResults = new Map<string, CheckResult[]>();
for (const c of CHECK_SEEDS) checkResults.set(c.id, []);

IMAGE_SEEDS.forEach((seed, index) => {
  const id = imageId(index);
  const { registry, repository, tag } = parseRef(seed.ref);
  const digest = `sha256:${hex(64)}`;
  const ok = SCANNERS.filter((s) => !seed.fail?.[s]);
  const findings = buildFindings(seed, ok);
  const { counts, fixable } = countFindings(findings);
  const score = imageVulnScore(findings, ok.length);
  const scannedAgo = (1 + Math.floor(rand() * 5)) * HOUR;
  const running = seed.running ?? true;

  const scans: ScannerRun[] = SCANNERS.map((s) => {
    const failure = seed.fail?.[s];
    const durationMs = failure?.status === 'timeout' ? 600_000 : Math.round(4_000 + rand() * (s === 'clair' ? 60_000 : 25_000));
    return {
      scanner: s,
      status: failure?.status ?? 'ok',
      scanId: 30,
      startedAt: iso(scannedAgo + durationMs),
      finishedAt: iso(scannedAgo),
      durationMs,
      version: SCANNER_VERSIONS[s],
      dbUpdatedAt: iso(SCANNER_DB_AGE_H[s] * HOUR),
      findings: findings.filter((f) => f.scanners.includes(s)).length,
      error: failure?.error ?? null,
    };
  });

  const agreement = findings.length
    ? Math.round((findings.reduce((a, f) => a + f.agreement, 0) / findings.length) * 100) / 100
    : ok.length
      ? 1
      : null;

  const usedBy: ContainerRef[] = [];
  for (const [namespace, kind, name] of seed.ns) {
    const replicas = kind === 'DaemonSet' ? 1 : kind === 'StatefulSet' ? 1 + Math.floor(rand() * 2) : 1 + Math.floor(rand() * 3);
    const containerName = repository.split('/').pop()?.replace(/[^a-z0-9-]/g, '-') ?? 'main';
    for (let r = 0; r < replicas; r += 1) {
      usedBy.push({ namespace, kind, name, container: containerName, pod: `${name}-${hex(5)}${kind === 'StatefulSet' ? '' : `-${hex(5)}`}`.replace(/-$/, ''), running, pack: seed.pack ?? null });
    }
    const key = `${namespace}/${kind}/${name}`;
    let acc = workloadMap.get(key);
    if (!acc) {
      acc = { namespace, kind, name, pack: seed.pack ?? (namespace === 'kube-system' ? null : null), containers: 0, images: [], results: new Map() };
      workloadMap.set(key, acc);
    }
    acc.containers += replicas;
    acc.images.push({ imageId: id, ref: seed.ref });
    // posture results for this container
    const system = namespace === 'kube-system' || namespace === 'longhorn-system';
    for (const check of CHECK_SEEDS) {
      let rate = system ? (check.systemFailRate ?? check.failRate) : check.failRate;
      if (check.id === 'mutable-tag') rate = tag === 'latest' ? 1 : 0;
      const fail = rand() < rate;
      const result: CheckResult = {
        namespace,
        kind,
        name,
        container: containerName,
        status: fail ? 'fail' : 'pass',
        detail: fail ? checkDetail(check.id, containerName) : null,
        systemNamespace: namespace === 'kube-system',
      };
      checkResults.get(check.id)?.push(result);
      acc.results.set(`${check.id}:${containerName}`, result);
    }
  }

  images.push({
    id,
    ref: seed.ref,
    registry,
    repository,
    tag,
    digest,
    score,
    grade: gradeForScore(score),
    counts,
    fixable,
    scanners: Object.fromEntries(
      scans.map((s) => [s.scanner, { status: s.status, findings: s.findings, durationMs: s.durationMs, error: s.error, version: s.version }]),
    ),
    agreementIndex: agreement,
    namespaces: [...new Set(seed.ns.map(([n]) => n))],
    workloads: new Set(seed.ns.map(([n, k, w]) => `${n}/${k}/${w}`)).size,
    containers: usedBy.length,
    running,
    lastScannedAt: iso(scannedAgo),
    mirrored: !seed.fail?.clair || seed.fail.clair.status !== 'error',
    warnings: [
      ...(seed.fail?.clair?.status === 'error' ? ['mirror failed; scanned original reference directly'] : []),
      ...(ok.length === 1 ? ['only one scanner succeeded: low confidence'] : []),
    ],
    confidence: ok.length <= 1 ? 'low' : 'normal',
    provenance: withScore(id, PROVENANCE_BY_REF[seed.ref], tag, scannedAgo),
    findings,
    usedBy,
    scans,
    postureFindings: [],
  });
});

function withScore(id: string, p: ImageDetail['provenance'], tag: string | null, scannedAgo: number): ImageDetail['provenance'] {
  if (!p) return null;
  if (p.sbom?.hasSBOM) p = { ...p, sbom: { ...p.sbom, downloadUrl: `/api/v1/images/${id}/sbom` } };
  const sc = supplyChainScore({ ...p, mutableTag: p.mutableTag ?? false }, { tag });
  const update = p.update ? { ...p.update, level: p.update.level ?? updateLevel(p.update) } : p.update;
  return { ...p, update, mutableTag: p.mutableTag ?? false, score: sc?.score ?? null, grade: sc?.grade ?? null, deductions: sc?.deductions ?? [], checkedAt: iso(scannedAgo + 90_000) };
}

function checkDetail(checkId: string, container: string): string {
  switch (checkId) {
    case 'privileged':
      return `container "${container}" has securityContext.privileged=true`;
    case 'host-namespaces':
      return 'pod spec sets hostNetwork=true';
    case 'host-path':
      return 'volume "host-root" mounts hostPath /var/lib';
    case 'run-as-root':
      return 'runAsNonRoot unset; image USER is root (uid 0)';
    case 'privilege-escalation':
      return 'allowPrivilegeEscalation not set (defaults to true)';
    case 'added-capabilities':
      return 'capabilities.add: [NET_ADMIN, SYS_ADMIN]';
    case 'capabilities-not-dropped':
      return 'capabilities.drop does not include ALL';
    case 'writable-rootfs':
      return 'readOnlyRootFilesystem not set';
    case 'no-resource-limits':
      return 'resources.limits.memory unset';
    case 'no-resource-requests':
      return 'resources.requests unset';
    case 'mutable-tag':
      return 'image uses tag "latest" without a digest';
    case 'no-liveness-probe':
      return 'no livenessProbe defined';
    case 'no-readiness-probe':
      return 'no readinessProbe defined';
    case 'automount-sa-token':
      return 'serviceAccountName=default, automountServiceAccountToken not false';
    case 'seccomp-unconfined':
      return 'seccompProfile unset at pod and container level';
    case 'no-netpol':
      return 'no NetworkPolicy selects this pod';
    default:
      return 'check failed';
  }
}

// posture findings per image
for (const image of images) {
  const keys = new Set(image.usedBy.map((u) => `${u.namespace}/${u.kind}/${u.name}`));
  const out: PostureFinding[] = [];
  for (const check of CHECK_SEEDS) {
    for (const r of checkResults.get(check.id) ?? []) {
      if (r.status === 'fail' && keys.has(`${r.namespace}/${r.kind}/${r.name}`) && r.container === image.usedBy[0]?.container) {
        out.push({ ...r, checkId: check.id, title: check.title, severity: check.severity, controls: check.controls });
      }
    }
  }
  image.postureFindings = out;
}

export const checks: Check[] = CHECK_SEEDS.map(({ failRate: _f, systemFailRate: _s, ...c }) => {
  const results = checkResults.get(c.id) ?? [];
  return { ...c, passed: results.filter((r) => r.status === 'pass').length, failed: results.filter((r) => r.status === 'fail').length };
});

export function checkDetailFor(id: string) {
  const check = checks.find((c) => c.id === id);
  if (!check) return null;
  const results = [...(checkResults.get(id) ?? [])].sort((a, b) => (a.status === b.status ? 0 : a.status === 'fail' ? -1 : 1));
  return { ...check, results };
}

const imageById = new Map(images.map((i) => [i.id, i]));

function sumCounts(list: SeverityCounts[]): SeverityCounts {
  const out = emptyCounts();
  for (const c of list) for (const k of Object.keys(out) as Severity[]) out[k] += c[k];
  return out;
}

function workloadPosture(acc: WorkloadAcc) {
  let failedWeight = 0;
  let passed = 0;
  let failed = 0;
  for (const [key, r] of acc.results) {
    const check = CHECK_SEEDS.find((c) => key.startsWith(`${c.id}:`));
    if (r.status === 'fail') {
      failed += 1;
      failedWeight += POSTURE_WEIGHT[check?.severity ?? 'low'] * (r.systemNamespace ? 0.5 : 1);
    } else passed += 1;
  }
  return { passed, failed, score: 100 * Math.exp(-failedWeight / 20) };
}

export const workloads: Workload[] = [...workloadMap.values()].map((acc) => {
  const imgs = acc.images.map((i) => imageById.get(i.imageId)).filter((i): i is ImageDetail => Boolean(i));
  const scored = imgs.filter((i) => i.score !== null);
  const vuln = scored.length ? scored.reduce((a, i) => a + (i.score ?? 0), 0) / scored.length : null;
  const posture = workloadPosture(acc);
  const score = vuln === null ? null : Math.round((0.7 * vuln + 0.3 * posture.score) * 10) / 10;
  return {
    namespace: acc.namespace,
    kind: acc.kind,
    name: acc.name,
    pack: acc.pack,
    score,
    grade: gradeForScore(score),
    images: acc.images,
    containers: acc.containers,
    posture: { passed: posture.passed, failed: posture.failed },
    counts: sumCounts(imgs.map((i) => i.counts)),
    // used for cluster aggregation below
    _postureScore: posture.score,
    _vuln: vuln,
  } as Workload & { _postureScore: number; _vuln: number | null };
});

const PACKS: Record<string, string | null> = {
  'kube-system': null,
  'envoy-gateway-system': 'nebari-system',
  'cert-manager': null,
  keycloak: 'keycloak',
  'nebari-system': 'nebari-system',
  jupyterhub: 'jupyterhub',
  monitoring: 'monitoring',
  'longhorn-system': null,
  minio: null,
  checkmaite: 'checkmaite',
  'security-posture': 'security-posture',
};

export const namespaces: Namespace[] = [...new Set(workloads.map((w) => w.namespace))].sort().map((name) => {
  const ws = workloads.filter((w) => w.namespace === name);
  const scored = ws.filter((w) => w.score !== null);
  const totalContainers = scored.reduce((a, w) => a + w.containers, 0);
  const score = totalContainers ? Math.round((scored.reduce((a, w) => a + (w.score ?? 0) * w.containers, 0) / totalContainers) * 10) / 10 : null;
  return {
    name,
    pack: PACKS[name] ?? null,
    managed: PACKS[name] !== null && PACKS[name] !== undefined,
    score,
    grade: gradeForScore(score),
    workloads: ws.length,
    images: new Set(ws.flatMap((w) => w.images.map((i) => i.imageId))).size,
    counts: sumCounts(ws.map((w) => w.counts)),
    posture: { passed: ws.reduce((a, w) => a + w.posture.passed, 0), failed: ws.reduce((a, w) => a + w.posture.failed, 0) },
  };
});

// cluster score
const internal = workloads as Array<Workload & { _postureScore: number; _vuln: number | null }>;
const weighted = internal.filter((w) => w._vuln !== null);
const wContainers = weighted.reduce((a, w) => a + w.containers, 0);
export const clusterVulnScore = Math.round((weighted.reduce((a, w) => a + (w._vuln ?? 0) * w.containers, 0) / wContainers) * 10) / 10;
export const clusterPostureScore = Math.round((internal.reduce((a, w) => a + w._postureScore * w.containers, 0) / internal.reduce((a, w) => a + w.containers, 0)) * 10) / 10;
// §12 supply-chain score: container-weighted mean over running containers
const scImages = images.filter((i) => i.running && typeof i.provenance?.score === 'number');
export const clusterSupplyChainScore =
  Math.round((scImages.reduce((a, i) => a + (i.provenance?.score ?? 0) * i.containers, 0) / scImages.reduce((a, i) => a + i.containers, 0)) * 10) / 10;
export const clusterScore = weightedClusterScore(clusterVulnScore, clusterPostureScore, clusterSupplyChainScore) as number;
for (const w of internal) {
  delete (w as Partial<typeof w>)._postureScore;
  delete (w as Partial<typeof w>)._vuln;
}

// ── Scans & trend ────────────────────────────────────────────────────────────
const SCAN_INTERVAL = 6 * HOUR;
export const scans: Scan[] = [];
for (let i = 0; i < 30; i += 1) {
  const id = i + 1;
  const ago = (30 - i) * SCAN_INTERVAL - 2 * HOUR;
  const status = id === 12 ? 'failed' : id === 21 ? 'cancelled' : 'done';
  const progress = i / 29;
  const drift = Math.sin(i / 3) * 2.2 + (rand() - 0.5) * 2;
  const score = status === 'done' ? Math.round((clusterScore - 9 * (1 - progress) + (i === 29 ? 0 : drift)) * 10) / 10 : null;
  const duration = (14 + rand() * 9) * 60_000;
  scans.push({
    id,
    trigger: id % 7 === 0 || id === 29 ? 'manual' : 'scheduled',
    status,
    startedAt: iso(ago),
    finishedAt: iso(ago - duration * (status === 'cancelled' ? 0.4 : 1)),
    imagesTotal: images.length,
    imagesDone: status === 'cancelled' ? 11 : status === 'failed' ? 3 : images.length,
    imagesFailed: status === 'failed' ? 3 : 1,
    score,
    grade: score === null ? null : gradeForScore(score),
    requestedBy: id % 7 === 0 || id === 29 ? 'nebari-admin' : null,
  });
}
scans[29].score = clusterScore;
scans[29].grade = gradeForScore(clusterScore);

export const SCAN_LOG_FAILED = [
  'scan 12: inventory complete: 27 unique images across 11 namespaces',
  'mirror: skopeo copy docker://docker.io/library/python:3.9-slim … ok',
  'trivy: connection refused dialing security-posture-trivy:4954',
  'ERROR scan aborted: trivy server unreachable after 5 retries',
];

export function scanLog(scan: Scan): string[] {
  if (scan.status === 'failed') return SCAN_LOG_FAILED;
  const lines = [
    `scan ${scan.id}: trigger=${scan.trigger} force=false`,
    `inventory: ${images.length} unique images across ${namespaces.length} namespaces (${workloads.length} workloads)`,
    'grype: db status ok (built ' + SCANNER_DB_AGE_H.grype + 'h ago)',
  ];
  for (const image of images.slice(0, Math.min(scan.imagesDone, images.length)).slice(-8)) {
    lines.push(`mirror ${image.ref} → registry.container-registry.svc.cluster.local:5000/posture-mirror/${image.repository}`);
    for (const s of image.scans) {
      lines.push(
        s.status === 'ok'
          ? `${s.scanner.padEnd(5)} ${image.ref}: ${s.findings} findings in ${(Number(s.durationMs) / 1000).toFixed(1)}s`
          : `${s.scanner.padEnd(5)} ${image.ref}: ${s.status.toUpperCase()} ${s.error ?? ''}`,
      );
    }
  }
  if (scan.status === 'done') lines.push(`scored: cluster ${scan.score ?? '—'} (${scan.grade ?? '?'})`);
  if (scan.status === 'cancelled') lines.push('scan cancelled by nebari-admin');
  return lines;
}

export function trend(): TrendPoint[] {
  return scans
    .filter((s) => s.status === 'done' && s.finishedAt)
    .slice(-30)
    .map((s) => {
      const k = Number(s.id) / scans.length;
      return {
        scanId: s.id,
        finishedAt: s.finishedAt as string,
        score: s.score,
        grade: (s.grade ?? '?') as Grade,
        critical: Math.round(totalCritical * (1.6 - 0.6 * k)),
        high: Math.round(totalHigh * (1.4 - 0.4 * k)),
      };
    });
}

// ── Summary ──────────────────────────────────────────────────────────────────
const runningImages = images.filter((i) => i.running);
const consensusCounts = sumCounts(runningImages.map((i) => i.counts));
const consensusFixable = sumCounts(runningImages.map((i) => ({ ...emptyCounts(), ...i.fixable })));
const totalCritical = consensusCounts.critical;
const totalHigh = consensusCounts.high;

export const scannerHealth: ScannerHealth[] = SCANNERS.map((name) => ({
  name,
  version: SCANNER_VERSIONS[name],
  dbUpdatedAt: iso(SCANNER_DB_AGE_H[name] * HOUR),
  healthy: name !== 'clair',
  lastError: name === 'clair' ? 'indexer: 1 image timed out (localhost:32000/checkmaite-frontend:latest)' : null,
}));

export function slaOverdue(): Partial<SeverityCounts> {
  const out = emptyCounts();
  for (const i of runningImages) for (const f of i.findings) if (f.overdue) out[f.severity] += 1;
  return { critical: out.critical, high: out.high, medium: out.medium, low: out.low };
}

export function buildSummary(): Summary {
  const last = scans[scans.length - 1];
  const allResults = [...checkResults.values()].flat();
  return {
    score: clusterScore,
    grade: gradeForScore(clusterScore),
    vulnScore: clusterVulnScore,
    postureScore: clusterPostureScore,
    supplyChainScore: clusterSupplyChainScore,
    generatedAt: last.finishedAt ?? new Date(NOW).toISOString(),
    lastScan: {
      id: last.id,
      status: last.status,
      startedAt: last.startedAt,
      finishedAt: last.finishedAt,
      imagesTotal: last.imagesTotal,
      imagesDone: last.imagesDone,
      imagesFailed: last.imagesFailed,
    },
    counts: consensusCounts,
    fixable: consensusFixable,
    images: { total: images.length, scanned: images.filter((i) => i.score !== null).length, failed: images.filter((i) => i.score === null).length },
    workloads: workloads.length,
    namespaces: namespaces.length,
    scanners: scannerHealth,
    trend: trend(),
    topRisks: [...images]
      .filter((i) => i.score !== null)
      .sort((a, b) => (a.score ?? 0) - (b.score ?? 0))
      .slice(0, 10)
      .map((i) => ({ imageId: i.id, ref: i.ref, score: i.score, grade: i.grade, critical: i.counts.critical, high: i.counts.high, workloads: i.workloads })),
    checks: {
      passed: allResults.filter((r) => r.status === 'pass').length,
      failed: allResults.filter((r) => r.status === 'fail').length,
      total: allResults.length,
    },
    warnings: SCANNERS.filter((s) => SCANNER_DB_AGE_H[s] > 72).map((s) => `${s} database is ${Math.round(SCANNER_DB_AGE_H[s] / 24)} days old`),
    slaOverdue: slaOverdue(),
  };
}

// ── Vulnerabilities (CVE-centric) ────────────────────────────────────────────
export function vulnIndex() {
  const map = new Map<string, { finding: Finding; images: ImageDetail[] }>();
  for (const image of images) {
    for (const f of image.findings) {
      const entry = map.get(f.vulnId);
      if (entry) {
        entry.images.push(image);
        const merged = maxSeverity([entry.finding.severity, f.severity]);
        if (merged) entry.finding = { ...entry.finding, severity: merged, scanners: SCANNERS.filter((s) => entry.finding.scanners.includes(s) || f.scanners.includes(s)) };
      } else map.set(f.vulnId, { finding: f, images: [image] });
    }
  }
  return map;
}

// ── Settings / me ────────────────────────────────────────────────────────────
export const me: Me = {
  username: 'nebari-admin',
  email: 'admin@nebari.example',
  groups: ['admin', 'developer', 'analyst'],
  isAdmin: true,
};

export const defaultSettings: Settings = {
  scanIntervalHours: 6,
  rescanAfterHours: 24,
  excludedNamespaces: ['kube-public'],
  scanners: { trivy: true, grype: true, clair: true },
  parallelism: 3,
  adminGroups: ['admin'],
  systemName: 'grace',
  organization: 'Nebari Dev',
  remediationSlaDays: { critical: 15, high: 30, medium: 90, low: 180 },
  reports: { autoGenerate: ['poam'] },
  provenance: {
    enabled: true,
    verifySignatures: true,
    cosignPublicKey: '',
    cosignCertificateIdentityRegexp: 'https://github.com/nebari-dev/.*',
    cosignCertificateOidcIssuerRegexp: 'https://token.actions.githubusercontent.com',
    checkSbom: true,
    checkProvenance: true,
    checkUpdates: true,
    updateLevel: 'minor',
    skipPrerelease: true,
    helmReleases: true,
    recheckHours: 24,
  },
  controlsEngine: { enabled: true, baseline: 'moderate', adminSubjects: ['nebari-admin', 'User/admin'] },
};

// ── §11 reports & compliance ─────────────────────────────────────────────────
export const reportTypes: ReportType[] = [
  { type: 'poam', title: 'POA&M', formats: ['xlsx', 'csv'], scopes: ['cluster', 'namespace', 'workload'], description: 'Plan of Action & Milestones in the eMASS POA&M import layout. One row per consensus finding per image, with NIST control, SLA-based scheduled completion and mitigation.' },
  { type: 'stig-checklist', title: 'STIG checklist', formats: ['ckl', 'cklb'], scopes: ['cluster', 'namespace', 'workload'], description: 'Kubernetes STIG / Container Platform SRG checklist for STIG Viewer 2.x (ckl) or 3 (cklb). Unmapped rules are Not_Reviewed.' },
  { type: 'sar', title: 'Automated Assessment Summary (input to SAR)', formats: ['pdf', 'html'], scopes: ['cluster', 'namespace'], description: 'Narrative input for the assessor\'s SAR: scope, methodology, hygiene index & trend, inventory, findings by severity, posture results, control evidence, scanner freshness, limitations.' },
  { type: 'oscal-ar', title: 'OSCAL Assessment Results', formats: ['json'], scopes: ['cluster'], description: 'OSCAL 1.1 assessment-results with observations, risks and findings tied to control ids (ra-5, si-2, cm-6 …), plus control-engine assertion observations.' },
  { type: 'oscal-ssp', title: 'OSCAL System Security Plan', formats: ['json'], scopes: ['cluster'], description: 'OSCAL 1.1.2 system-security-plan: control-implementation statements per component with live assertion status and links to evidence, for the selected NIST baseline.' },
  { type: 'oscal-component-definition', title: 'OSCAL Component Definition', formats: ['json'], scopes: ['cluster'], description: 'OSCAL component-definition for the platform components (Keycloak, Envoy Gateway, cert-manager, Kubernetes, logging, this pack) and the controls each implements or inherits.' },
  { type: 'inventory', title: 'Software inventory', formats: ['xlsx', 'csv'], scopes: ['cluster', 'namespace'], description: 'eMASS-style hardware/software inventory: image, digest, registry, version, namespaces, workloads, running count, scanner coverage.' },
  { type: 'vuln-export', title: 'Vulnerability export', formats: ['csv', 'json'], scopes: ['cluster', 'namespace', 'workload'], description: 'Flat (image, CVE, package) export with all three scanners’ severities for ACAS-style trackers.' },
];

export const reports: Report[] = [
  { id: 'rpt-0007', type: 'sar', format: 'pdf', scope: { kind: 'cluster' }, scanId: 30, status: 'running', createdAt: iso(40_000), createdBy: 'nebari-admin', sizeBytes: null, filename: null },
  { id: 'rpt-0006', type: 'poam', format: 'xlsx', scope: { kind: 'cluster' }, scanId: 30, status: 'done', createdAt: iso(2 * HOUR), createdBy: 'system (auto)', sizeBytes: 48_213, filename: 'grace-poam-scan30.xlsx' },
  { id: 'rpt-0005', type: 'stig-checklist', format: 'ckl', scope: { kind: 'namespace', name: 'jupyterhub' }, scanId: 30, status: 'done', createdAt: iso(3 * HOUR), createdBy: 'nebari-admin', sizeBytes: 211_904, filename: 'grace-jupyterhub-k8s-stig-scan30.ckl' },
  { id: 'rpt-0004', type: 'oscal-ar', format: 'json', scope: { kind: 'cluster' }, scanId: 29, status: 'failed', createdAt: iso(9 * HOUR), createdBy: 'nebari-admin', sizeBytes: null, filename: null, error: 'OSCAL schema validation failed: /assessment-results/results/0/findings/12/target/status/state: must be one of [satisfied, not-satisfied]' },
  { id: 'rpt-0003', type: 'inventory', format: 'csv', scope: { kind: 'cluster' }, scanId: 29, status: 'done', createdAt: iso(10 * HOUR), createdBy: 'nebari-admin', sizeBytes: 9_870, filename: 'grace-inventory-scan29.csv' },
  { id: 'rpt-0002', type: 'vuln-export', format: 'json', scope: { kind: 'workload', name: 'checkmaite/Deployment/checkmaite-frontend' }, scanId: 28, status: 'done', createdAt: iso(20 * HOUR), createdBy: 'nebari-admin', sizeBytes: 31_455, filename: 'grace-checkmaite-frontend-vulns-scan28.json' },
  { id: 'rpt-0001', type: 'poam', format: 'xlsx', scope: { kind: 'cluster' }, scanId: 28, status: 'done', createdAt: iso(26 * HOUR), createdBy: 'system (auto)', sizeBytes: 47_002, filename: 'grace-poam-scan28.xlsx' },
];

const CONTROL_TITLES: Record<string, string> = {
  'RA-5': 'Vulnerability Monitoring and Scanning',
  'SI-2': 'Flaw Remediation',
  'SI-2(2)': 'Automated Flaw Remediation Status',
  'AC-6': 'Least Privilege',
  'AC-6(10)': 'Prohibit Non-privileged Users from Executing Privileged Functions',
  'CM-7': 'Least Functionality',
  'SC-7': 'Boundary Protection',
  'SC-6': 'Resource Availability',
  'CM-2': 'Baseline Configuration',
  'CM-14': 'Signed Components',
  'SI-13': 'Predictable Failure Prevention',
  'IA-5': 'Authenticator Management',
  'CM-6': 'Configuration Settings',
  'SI-16': 'Memory Protection',
  'AC-4': 'Information Flow Enforcement',
};

/** §11 per-control counts merged into the §13 catalog. */
export function controlCoverage(): ControlCoverage[] {
  const findingsOpen = new Map<string, number>();
  for (const image of runningImages) for (const f of image.findings) for (const c of f.controls ?? []) findingsOpen.set(c, (findingsOpen.get(c) ?? 0) + 1);
  const checksFailed = new Map<string, number>();
  for (const c of checks) for (const ctl of c.controls ?? []) checksFailed.set(ctl, (checksFailed.get(ctl) ?? 0) + c.failed);
  const extra = new Map(Object.keys(CONTROL_TITLES).map((control) => [control, { findingsOpen: findingsOpen.get(control) ?? 0, checksFailed: checksFailed.get(control) ?? 0 }]));
  return controlCatalog(extra);
}

// ── §12 supply chain ─────────────────────────────────────────────────────────
export function supplyChainSummary(): SupplyChainSummary {
  const p = images.map((i) => i.provenance);
  return {
    signed: p.filter((x) => x?.signature?.signed).length,
    verified: p.filter((x) => x?.signature?.verified).length,
    withSbom: p.filter((x) => x?.sbom?.hasSBOM).length,
    withProvenance: p.filter((x) => x?.provenance?.hasProvenance).length,
    withUpdates: p.filter((x) => x?.update?.updateAvailable).length,
    unique: images.length,
    helmReleases: helmReleases.length,
    helmWithUpdates: helmReleases.filter((h) => h.update?.updateAvailable).length,
    score: clusterSupplyChainScore,
    grade: gradeForScore(clusterSupplyChainScore),
  };
}

export function stigRules(): StigRule[] {
  const mapped: StigRule[] = CHECK_SEEDS.filter((c) => c.stig).map((c) => {
    const offenders = (checkResults.get(c.id) ?? []).filter((r) => r.status === 'fail');
    const unique = [...new Map(offenders.map((o) => [`${o.namespace}/${o.kind}/${o.name}`, { namespace: o.namespace, kind: o.kind, name: o.name, container: o.container }])).values()];
    return {
      vulnId: c.stig?.vulnId ?? '',
      ruleId: c.stig?.ruleId ?? '',
      title: c.title,
      cat: c.stig?.cat ?? 'II',
      status: unique.length ? 'Open' : 'NotAFinding',
      offenders: unique,
      checkId: c.id,
    };
  });
  const notReviewed: StigRule[] = [
    { vulnId: 'V-242376', ruleId: 'SV-242376r879519_rule', title: 'The Kubernetes Controller Manager must use TLS 1.2, at a minimum', cat: 'II', status: 'Not_Reviewed', offenders: [], checkId: null },
    { vulnId: 'V-242381', ruleId: 'SV-242381r879530_rule', title: 'The Kubernetes Controller Manager must create unique service accounts for each work payload', cat: 'I', status: 'Not_Reviewed', offenders: [], checkId: null },
    { vulnId: 'V-242386', ruleId: 'SV-242386r879530_rule', title: 'The Kubernetes API server must have the insecure port flag disabled', cat: 'I', status: 'Not_Reviewed', offenders: [], checkId: null },
    { vulnId: 'V-242400', ruleId: 'SV-242400r879530_rule', title: 'The Kubernetes API server must have Alpha APIs disabled', cat: 'II', status: 'Not_Reviewed', offenders: [], checkId: null },
    { vulnId: 'V-242442', ruleId: 'SV-242442r879825_rule', title: 'Kubernetes must remove old components after updated versions have been installed', cat: 'II', status: 'Not_Reviewed', offenders: [], checkId: null },
    { vulnId: 'V-242461', ruleId: 'SV-242461r879887_rule', title: 'Kubernetes API Server audit logs must be enabled', cat: 'III', status: 'Not_Reviewed', offenders: [], checkId: null },
  ];
  const compliant: StigRule = { vulnId: 'V-245541', ruleId: 'SV-245541r879604_rule', title: 'Kubernetes Kubelet must not disable timeouts', cat: 'II', status: 'NotAFinding', offenders: [], checkId: null };
  return [...mapped, compliant, ...notReviewed];
}

export function scanDetail(scan: Scan) {
  const perScanner = Object.fromEntries(
    SCANNERS.map((s) => [s, { ok: images.slice(0, scan.imagesDone).filter((i) => i.scanners[s]?.status === 'ok').length, error: images.slice(0, scan.imagesDone).filter((i) => i.scanners[s] && i.scanners[s]?.status !== 'ok').length }]),
  );
  return {
    ...scan,
    perScanner,
    log: scanLog(scan),
    warnings: scan.status === 'done' ? ['grype database is 4 days old', 'ghcr.io/acme-internal/batch-agent:1.4.0: all scanners failed'] : [],
  };
}
