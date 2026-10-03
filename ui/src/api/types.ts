/**
 * TypeScript mirror of docs/DESIGN.md §5 (API) and §11 (compliance reports).
 * Fields marked "assumed" are not spelled out in the contract; the UI reads
 * them defensively (optional) so a slightly different API shape degrades
 * gracefully rather than crashing.
 */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const GRADES = ['A', 'B', 'C', 'D', 'F', '?'] as const;
export type Grade = (typeof GRADES)[number];

export const SCANNERS = ['trivy', 'grype', 'clair'] as const;
export type ScannerName = (typeof SCANNERS)[number];

export type SeverityCounts = Record<Severity, number>;

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

// ── /me ──────────────────────────────────────────────────────────────────────
export interface Me {
  username: string;
  email: string;
  groups: string[];
  isAdmin: boolean;
}

// ── /summary ─────────────────────────────────────────────────────────────────
export type ScanStatus = 'queued' | 'running' | 'done' | 'failed' | 'cancelled';
export type ScanTrigger = 'manual' | 'scheduled';

export interface LastScan {
  id: number | string;
  status: ScanStatus;
  startedAt: string | null;
  finishedAt: string | null;
  imagesTotal: number;
  imagesDone: number;
  imagesFailed: number;
}

export interface ScannerHealth {
  name: ScannerName;
  version: string | null;
  dbUpdatedAt: string | null;
  healthy: boolean;
  lastError: string | null;
}

export interface TrendPoint {
  scanId: number | string;
  finishedAt: string;
  score: number | null;
  grade: Grade;
  critical: number;
  high: number;
}

export interface TopRisk {
  imageId: string;
  ref: string;
  score: number | null;
  grade: Grade;
  critical: number;
  high: number;
  workloads: number;
}

export interface PassFail {
  passed: number;
  failed: number;
}

export interface Summary {
  score: number | null;
  grade: Grade;
  vulnScore: number | null;
  postureScore: number | null;
  generatedAt: string;
  lastScan: LastScan | null;
  counts: SeverityCounts;
  fixable: Partial<SeverityCounts>;
  /** The latest done scan's unique images (its `imagesTotal` on a full scan); `running` = with a Running pod. */
  images: { total: number; scanned: number; failed: number; running?: number };
  workloads: number;
  namespaces: number;
  scanners: ScannerHealth[];
  trend: TrendPoint[];
  topRisks: TopRisk[];
  checks: { passed: number; failed: number; total: number };
  /** SCORING.md "Scanner freshness". */
  warnings?: string[];
  /** §11 remediation SLA. */
  slaOverdue?: Partial<SeverityCounts>;
  /** §12 cluster supply-chain score (0.6/0.25/0.15 split once present). */
  supplyChainScore?: number | null;
}

// ── images ───────────────────────────────────────────────────────────────────
export type ScannerRunStatus = 'ok' | 'error' | 'timeout' | 'unsupported' | 'skipped';

export interface ScannerRunSummary {
  status: ScannerRunStatus;
  findings: number;
  durationMs: number | null;
  error?: string | null;
  version?: string | null;
}

export interface ImageSummary {
  id: string;
  ref: string;
  registry: string;
  repository: string;
  tag: string | null;
  digest: string | null;
  score: number | null;
  grade: Grade;
  counts: SeverityCounts;
  fixable: Partial<SeverityCounts>;
  scanners: Partial<Record<ScannerName, ScannerRunSummary>>;
  agreementIndex: number | null;
  namespaces: string[];
  workloads: number;
  containers: number;
  running: boolean;
  /** In the latest done scan's inventory; `false` = stale (no longer deployed), null before any scan. */
  current?: boolean | null;
  lastScannedAt: string | null;
  mirrored: boolean;
  warnings: string[];
  /** SCORING.md: `low` when only one scanner succeeded (assumed field). */
  confidence?: 'low' | 'normal';
  /** §12 supply-chain provenance (absent before §12 ships). */
  provenance?: ImageProvenance | null;
}

// ── §12 supply-chain provenance ──────────────────────────────────────────────
/** provenance-collector-pack `SignatureInfo`. */
export interface SignatureInfo {
  signed: boolean;
  verified: boolean;
  error?: string | null;
  /** assumed: `key` | `keyless` — how verification was attempted. */
  mode?: string | null;
}

/** provenance-collector-pack `SBOMInfo` (+ assumed download link). */
export interface SbomInfo {
  hasSBOM: boolean;
  format?: string | null;
  /** assumed: link to the stored SBOM attestation, when the API exposes one. */
  downloadUrl?: string | null;
}

/** provenance-collector-pack `ProvenanceInfo`. */
export interface ProvenanceInfo {
  hasProvenance: boolean;
  predicateType?: string | null;
  /** assumed: SLSA builder id, when present in the predicate. */
  builder?: string | null;
}

/** provenance-collector-pack `UpdateInfo`. */
export interface UpdateInfo {
  currentTag: string;
  latestInMajor?: string | null;
  newestAvailable?: string | null;
  updateAvailable: boolean;
  /** assumed: how far behind (`patch`|`minor`|`major`); derived from tags when absent. */
  level?: UpdateLevel | null;
}

export type UpdateLevel = 'patch' | 'minor' | 'major';

/** assumed: one itemised supply-chain score deduction. */
export interface SupplyChainDeduction {
  reason: string;
  points: number;
}

/** `ImageSummary.provenance` (§12). Every member optional: a check that didn't run is absent. */
export interface ImageProvenance {
  signature?: SignatureInfo | null;
  sbom?: SbomInfo | null;
  provenance?: ProvenanceInfo | null;
  update?: UpdateInfo | null;
  /** assumed: per-image supply-chain score; recomputed client-side when absent. */
  score?: number | null;
  grade?: Grade | null;
  deductions?: SupplyChainDeduction[] | null;
  /** assumed: tag is mutable (latest/missing) and the spec doesn't pin a digest. */
  mutableTag?: boolean | null;
  checkedAt?: string | null;
}

/** `GET /supply-chain`. */
export interface SupplyChainSummary {
  signed: number;
  verified: number;
  withSbom: number;
  withProvenance: number;
  withUpdates: number;
  unique: number;
  helmReleases: number;
  helmWithUpdates: number;
  score: number | null;
  grade: Grade;
  /** Images left out because they are not in the latest done scan (`?includeStale=true` adds them). */
  stale?: number;
  includeStale?: boolean;
}

/** `GET /helm-releases` (provenance-collector-pack `HelmRecord`). */
export interface HelmRelease {
  releaseName: string;
  namespace: string;
  chart: string;
  version: string;
  appVersion: string;
  status: string;
  update?: UpdateInfo | null;
}

export interface Finding {
  vulnId: string;
  severity: Severity;
  package: string;
  installedVersion: string;
  fixedVersion: string | null;
  pkgType: string;
  scanners: ScannerName[];
  agreement: number;
  perScanner: Partial<Record<ScannerName, Severity>>;
  cvss: number | null;
  title: string | null;
  url: string | null;
  fixable: boolean;
  /** §11 NIST 800-53 tags. */
  controls?: string[];
  firstSeenAt?: string | null;
  slaDueAt?: string | null;
  overdue?: boolean;
}

/** Assumed shape for `usedBy[]`. */
export interface ContainerRef {
  namespace: string;
  kind: string;
  name: string;
  container: string;
  pod?: string;
  running: boolean;
  pack?: string | null;
}

/** Assumed shape for `scans[]` on ImageDetail. */
export interface ScannerRun {
  scanner: ScannerName;
  status: ScannerRunStatus;
  scanId?: number | string;
  startedAt?: string | null;
  finishedAt?: string | null;
  durationMs: number | null;
  version?: string | null;
  dbUpdatedAt?: string | null;
  findings: number;
  error?: string | null;
}

export type CheckResultStatus = 'pass' | 'fail';

export interface CheckResult {
  namespace: string;
  kind: string;
  name: string;
  container: string | null;
  status: CheckResultStatus;
  detail: string | null;
  systemNamespace?: boolean;
}

/** Assumed shape for `postureFindings[]` on ImageDetail. */
export interface PostureFinding extends CheckResult {
  checkId: string;
  title?: string;
  severity: Severity;
  controls?: string[];
}

export interface ImageDetail extends ImageSummary {
  findings: Finding[];
  usedBy: ContainerRef[];
  scans: ScannerRun[];
  postureFindings: PostureFinding[];
}

export interface ImageQuery {
  namespace?: string;
  grade?: string;
  severity?: string;
  q?: string;
  /** true = only images in the latest done scan, false = only stale ones. */
  current?: boolean;
  sort?: string;
  order?: 'asc' | 'desc';
  page?: number;
  pageSize?: number;
}

// ── vulnerabilities ──────────────────────────────────────────────────────────
export interface VulnSummary {
  vulnId: string;
  severity: Severity;
  scanners: ScannerName[];
  agreement: number;
  imagesAffected: number;
  workloadsAffected: number;
  fixAvailable: boolean;
  cvss: number | null;
  title: string | null;
  url: string | null;
  controls?: string[];
}

export interface VulnList {
  items: VulnSummary[];
  total: number;
  page?: number;
  pageSize?: number;
}

/** Assumed shape for an affected image on the CVE detail. */
export interface AffectedImage {
  imageId: string;
  ref: string;
  grade: Grade;
  score: number | null;
  package: string;
  installedVersion: string;
  fixedVersion: string | null;
  perScanner: Partial<Record<ScannerName, Severity>>;
  namespaces: string[];
  workloads: number;
}

export interface VulnDetail extends VulnSummary {
  description?: string | null;
  images: AffectedImage[];
}

export interface VulnQuery {
  severity?: string;
  q?: string;
  fixable?: boolean;
  page?: number;
  pageSize?: number;
}

// ── workloads / namespaces ───────────────────────────────────────────────────
export interface Workload {
  namespace: string;
  kind: string;
  name: string;
  pack: string | null;
  score: number | null;
  grade: Grade;
  images: { imageId: string; ref: string }[];
  containers: number;
  posture: PassFail;
  counts: SeverityCounts;
}

export interface Namespace {
  name: string;
  pack: string | null;
  managed: boolean;
  score: number | null;
  grade: Grade;
  workloads: number;
  images: number;
  counts: SeverityCounts;
  posture: PassFail;
}

// ── checks ───────────────────────────────────────────────────────────────────
export interface StigRef {
  vulnId: string;
  ruleId: string;
  cat?: StigCat;
}

export interface Check {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  remediation: string;
  passed: number;
  failed: number;
  controls?: string[];
  stig?: StigRef | null;
}

export interface CheckDetail extends Check {
  results: CheckResult[];
}

// ── scans ────────────────────────────────────────────────────────────────────
export interface Scan {
  id: number | string;
  trigger: ScanTrigger;
  status: ScanStatus;
  startedAt: string | null;
  finishedAt: string | null;
  imagesTotal: number;
  imagesDone: number;
  imagesFailed: number;
  score: number | null;
  grade: Grade | null;
  requestedBy: string | null;
}

export interface ScanDetail extends Scan {
  perScanner: Partial<Record<ScannerName, { ok: number; error: number }>>;
  /** "recent log lines" — field name assumed; client normalises `logs`/`logTail`. */
  log: string[];
  warnings?: string[];
}

export interface ScanCreate {
  force?: boolean;
  imageIds?: string[];
  namespaces?: string[];
}

export interface Scanner {
  name: ScannerName;
  enabled: boolean;
  version: string | null;
  dbUpdatedAt: string | null;
  healthy: boolean;
  lastError: string | null;
  lastRunAt: string | null;
}

// ── settings ─────────────────────────────────────────────────────────────────
export interface Settings {
  scanIntervalHours: number;
  rescanAfterHours: number;
  excludedNamespaces: string[];
  scanners: Record<ScannerName, boolean>;
  parallelism: number;
  /** read-only */
  adminGroups: string[];
  systemName?: string;
  organization?: string;
  remediationSlaDays?: { critical: number; high: number; medium: number; low: number };
  reports?: { autoGenerate: string[] };
  /** §12 */
  provenance?: ProvenanceSettings;
  /** §13 */
  controlsEngine?: ControlsEngineSettings;
}

export type Baseline = 'low' | 'moderate' | 'high';
export const BASELINES: Baseline[] = ['low', 'moderate', 'high'];

/**
 * §12 `provenance` settings — flat, as served by the API's `ProvenanceSettings`.
 * Key vs keyless is implied: a non-empty `cosignPublicKey` means key mode.
 */
export interface ProvenanceSettings {
  enabled?: boolean;
  verifySignatures: boolean;
  cosignPublicKey: string;
  cosignCertificateIdentityRegexp: string;
  cosignCertificateOidcIssuerRegexp: string;
  checkSbom: boolean;
  checkProvenance: boolean;
  checkUpdates: boolean;
  updateLevel: UpdateLevel;
  skipPrerelease: boolean;
  helmReleases: boolean;
  recheckHours?: number;
}

/** §13 `controlsEngine` settings (`enabled` is read-only: set from Helm values). */
export interface ControlsEngineSettings {
  enabled: boolean;
  baseline: Baseline;
  adminSubjects: string[];
}

// ── §11 reports & compliance ─────────────────────────────────────────────────
export type ReportScopeKind = 'cluster' | 'namespace' | 'workload';
export type ReportStatus = 'queued' | 'running' | 'done' | 'failed';

export interface ReportType {
  type: string;
  formats: string[];
  scopes: ReportScopeKind[];
  description: string;
  title?: string;
}

export interface ReportScope {
  kind: ReportScopeKind;
  name?: string | null;
}

export interface Report {
  id: string | number;
  type: string;
  format: string;
  scope: ReportScope;
  scanId: number | string | null;
  status: ReportStatus;
  createdAt: string;
  createdBy: string | null;
  sizeBytes: number | null;
  filename: string | null;
  error?: string | null;
}

export interface ReportCreate {
  type: string;
  format: string;
  scope?: ReportScope;
  scanId?: number | string;
  options?: { rollupByCve?: boolean; systemName?: string; includeSystemNamespaces?: boolean };
}

/** §13 control implementation status. Older APIs return `satisfied`/`not-satisfied`; normalised client-side. */
export type ControlStatus = 'implemented' | 'partial' | 'not-implemented' | 'inherited' | 'not-applicable' | 'unknown';
export type AssertionStatus = 'pass' | 'fail' | 'unknown' | 'not-applicable';

export interface ControlAssertion {
  id: string;
  title: string;
  status: AssertionStatus | string;
  evidence?: unknown;
  checkedAt?: string | null;
  /** assumed: one-line human summary (`detail` from evaluate()). */
  detail?: string | null;
}

/** `GET /compliance/controls` (§11 shape extended by §13; new fields optional). */
export interface ControlCoverage {
  control: string;
  title: string;
  findingsOpen: number;
  checksFailed: number;
  status: string;
  family?: string | null;
  /** lowest baseline containing the control (`low`…), or a list of baselines; null = not in a baseline. */
  baseline?: string | string[] | null;
  /** In the selected baseline (§13 API); derived from `baseline` when absent. */
  inBaseline?: boolean;
  components?: string[];
  assertions?: ControlAssertion[];
}

/** Control counts by status (`GET /compliance/families` `totals.*`). */
export interface ComplianceTotals {
  total: number;
  implemented: number;
  partial: number;
  notImplemented: number;
  inherited: number;
  notApplicable: number;
  unknown: number;
}

/**
 * `GET /compliance/families`: per-family rollup of the selected baseline (`items`) plus
 * totals for the baseline and for every control `GET /compliance/controls` lists (`catalog`).
 * Older APIs return the bare `items` array.
 */
export interface FamiliesRollup {
  baseline?: string;
  items: FamilyRollup[];
  totals?: { baseline: ComplianceTotals & { name?: string }; catalog: ComplianceTotals };
}

/** One family row of `GET /compliance/families`. */
export interface FamilyRollup {
  family: string;
  title: string;
  implemented: number;
  partial: number;
  notImplemented: number;
  inherited: number;
  notApplicable: number;
  unknown: number;
}

/** `GET /compliance/assertions`. */
export interface Assertion extends ControlAssertion {
  controls: string[];
  component: string;
  severity?: string;
}

/** `POST /compliance/assertions/run` 202 body (a queued run row). */
export interface AssertionRun {
  status: string;
  createdAt?: string | null;
  startedAt?: string | null;
  id?: string | number | null;
}

export type StigCat = 'I' | 'II' | 'III';
export type StigStatus = 'Open' | 'NotAFinding' | 'Not_Reviewed';

export interface StigOffender {
  namespace: string;
  kind: string;
  name: string;
  container?: string | null;
}

export interface StigRule {
  vulnId: string;
  ruleId: string;
  title: string;
  cat: StigCat | string;
  status: StigStatus | string;
  /** count or list of offending workloads (shape assumed; both are rendered). */
  offenders: number | Array<string | StigOffender>;
  checkId?: string | null;
}
