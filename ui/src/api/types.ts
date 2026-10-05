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
export type ScanTrigger = 'manual' | 'scheduled' | 'event';

export interface LastScan {
  id: number | string;
  status: ScanStatus;
  startedAt: string | null;
  finishedAt: string | null;
  imagesTotal: number;
  imagesDone: number;
  imagesFailed: number;
}

/** Vulnerability scanners plus §14 `scap` (OpenSCAP), which reports benchmark content, not a vuln DB. */
export type HealthScannerName = ScannerName | 'scap';

export interface ScannerHealth {
  name: HealthScannerName;
  version: string | null;
  dbUpdatedAt: string | null;
  healthy: boolean;
  lastError: string | null;
  /** §14 `scap`: SCAP content in the catalogue (`dbUpdatedAt` = last content fetch). */
  contentVersions?: ScapContentVersion[];
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
  /** §14 product/OS STIG rollup over current images (absent before §14 / with SCAP off). */
  stig?: StigRollup | null;
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
  /** §14 per-image STIG summary; `null` = no applicable benchmark, absent = API without §14. */
  stig?: ImageStigBrief | null;
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

/** Summary over the filtered findings set of `GET /images/{id}` (not just the returned page). */
export interface FindingsSummary {
  /** all findings of the image, ignoring filters */
  total: number;
  /** findings matching the filters (= `findingsTotal`) */
  filtered: number;
  bySeverity: Record<Severity, number>;
  fixable: number;
  /** filtered findings reported by every scanner that succeeded (0 when fewer than 2 succeeded) */
  flaggedByAll: number;
  scannersOk: number;
}

export interface ImageDetail extends ImageSummary {
  /** One page of findings when `page` is sent; otherwise the first 500 (see `truncated`). */
  findings: Finding[];
  findingsTotal?: number;
  findingsPage?: number;
  findingsPageSize?: number;
  /** true when `page` was not sent and more than 500 findings matched (the list is cut). */
  truncated?: boolean;
  findingsSummary?: FindingsSummary;
  usedBy: ContainerRef[];
  scans: ScannerRun[];
  postureFindings: PostureFinding[];
}

export type FindingSort = 'severity' | 'cvss' | 'vulnId' | 'package' | 'agreement' | 'firstSeenAt';

/** Server-side paging/filtering of the findings on `GET /images/{id}` (DECISIONS 2026-10-03). */
export interface ImageFindingsQuery {
  page?: number;
  /** default 50, max 500 */
  pageSize?: number;
  /** comma-separated severities */
  severity?: string;
  /** substring of vulnId, package or title (case-insensitive) */
  q?: string;
  fixable?: boolean;
  /** only findings not reported by every scanner that succeeded */
  disagree?: boolean;
  sort?: FindingSort;
  order?: 'asc' | 'desc';
}

export interface ImageQuery {
  namespace?: string;
  grade?: string;
  severity?: string;
  q?: string;
  /** true = only images in the latest done scan, false = only stale ones. */
  current?: boolean;
  /** §14 (assumed): `evaluated` | `na` | `cat1` (has open CAT I). */
  stig?: string;
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
  /** Unique images in the scan's inventory snapshot (null on scans before migration 0006). */
  imagesInventoried?: number | null;
  /** Images (re)scanned by this scan: stale, forced or targeted. */
  imagesRescanned?: number | null;
  /** Candidate images skipped because their last scan is still fresh (rescanAfterHours). */
  imagesSkippedFresh?: number | null;
  /** Targeted / event scans: images the scan was aimed at; null for full scans. */
  imagesTargeted?: number | null;
  targetNamespaces?: string[] | null;
  score: number | null;
  grade: Grade | null;
  requestedBy: string | null;
  /** §14: null (SCAP off) | queued | running | done | skipped | failed */
  scapStatus?: string | null;
  scapImages?: number | null;
  /** images of the scan's SCAP stage evaluated so far */
  scapProgress?: { done: number; total: number } | null;
  /** finalized before its SCAP stage completed: scores without the new STIG results, auto-reports / controls deferred */
  scapPending?: boolean;
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
  name: HealthScannerName;
  enabled: boolean;
  version: string | null;
  dbUpdatedAt: string | null;
  healthy: boolean;
  lastError: string | null;
  lastRunAt: string | null;
  /** §14 `scap` only. */
  contentVersions?: ScapContentVersion[];
}

// ── settings ─────────────────────────────────────────────────────────────────
export interface Settings {
  scanIntervalHours: number;
  rescanAfterHours: number;
  excludedNamespaces: string[];
  /** `scap` (§14) is optional: absent on APIs without the SCAP stage. */
  scanners: Record<ScannerName, boolean> & { scap?: boolean };
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
  /** §14 */
  scap?: ScapSettings;
}

/** §14 `scap` settings. `sources` is read-only here (Helm `scap.content.sources[]`). */
export interface ScapSettings {
  sources: ScapContentSource[];
  preferDisa: boolean;
  timeoutSeconds: number;
}

/** API `ScapSource`: `{name, kind (ssg|disa|custom), url, sha256, include[]}`. */
export interface ScapContentSource {
  url: string;
  sha256?: string | null;
  name?: string | null;
  kind?: string | null;
  include?: string[];
  /** assumed alias of `kind` */
  source?: string | null;
  /** assumed: content version (otherwise matched from the `scap` scanner's content list) */
  version?: string | null;
  fetchedAt?: string | null;
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

/**
 * §13 control *evidence* status (compliance review M2/M8: evidence for an assessor, never an
 * assessment result). Older APIs return `implemented`/`not-implemented`/`unknown`/`satisfied`; normalised client-side.
 */
export type ControlStatus =
  | 'passing'
  | 'partial'
  | 'failing'
  | 'hybrid'
  | 'inherited'
  | 'org-provided-unverified'
  | 'not-applicable'
  | 'not-assessed';
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
  /** CRM responsibility: provider | shared | customer | org. */
  responsibility?: string | null;
  /** Common control provider, when inherited. */
  provider?: string | null;
  /** SP 800-53A objectives with their evidence state (satisfied | not-satisfied | unknown | assigned | no-evidence). */
  objectives?: Array<{ id: string; state: string; assertions?: string[] }>;
}

/** Control counts by status (`GET /compliance/families` `totals.*`). */
export interface ComplianceTotals {
  total: number;
  passing: number;
  partial: number;
  failing: number;
  hybrid: number;
  inherited: number;
  orgProvided: number;
  notApplicable: number;
  notAssessed: number;
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
  passing: number;
  partial: number;
  failing: number;
  hybrid: number;
  inherited: number;
  orgProvided: number;
  notApplicable: number;
  notAssessed: number;
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

// ── §14 SCAP scanner (product and OS STIGs inside images) ───────────────────
export type ScapSource = 'disa' | 'ssg';
export const SCAP_RESULTS = ['pass', 'fail', 'notapplicable', 'notchecked', 'error', 'unknown', 'informational'] as const;
export type ScapResult = (typeof SCAP_RESULTS)[number];
/** STIG severity category (CAT I = high). */
export type ScapCat = 'cat1' | 'cat2' | 'cat3';
export const SCAP_CATS: ScapCat[] = ['cat1', 'cat2', 'cat3'];

/** `GET /summary` `stig`. `coverage` = share of current images with a benchmark (0–1 or 0–100). */
export interface StigRollup {
  evaluated: number;
  pass: number;
  fail: number;
  cat1Open: number;
  cat2Open: number;
  cat3Open: number;
  coverage: number | null;
  /** API extras: images with no applicable benchmark / no content / errors / not yet evaluated, and their total */
  notApplicable?: number;
  noContent?: number;
  errors?: number;
  pending?: number;
  /** kept results whose last re-evaluation failed transiently (counted under their status too) */
  stale?: number;
  images?: number;
  score?: number | null;
}

/** `ImageSummary.stig` (fields beyond `score` assumed and optional). */
export interface ImageStigBrief {
  /** evaluated | notApplicable | noContent | error | timeout | notEvaluated */
  status?: string | null;
  score: number | null;
  fidelity?: string | null;
  error?: string | null;
  benchmarks?: number;
  pass?: number;
  fail?: number;
  cat1Open?: number;
  cat2Open?: number;
  cat3Open?: number;
  /** the last re-evaluation failed transiently (registry 429, timeout): this is the previous result */
  stale?: boolean;
  staleError?: string | null;
  staleSince?: string | null;
}

/** Per-(image, benchmark) summary. */
export interface ImageStigSummary {
  benchmark?: string | null;
  profile?: string | null;
  pass: number;
  fail: number;
  notapplicable: number;
  notchecked: number;
  error: number;
  score: number | null;
  /** assumed: open (failed) rules per category over the whole benchmark */
  cat1Open?: number;
  cat2Open?: number;
  cat3Open?: number;
  rootfsFidelity?: string | null;
  evaluatedAt?: string | null;
}

export interface ScapRule {
  ruleId: string;
  /** V-/SV- id when present */
  stigId: string | null;
  cci: string[];
  severity: ScapCat;
  result: ScapResult | string;
  title: string;
  fixText?: string | null;
  checkedAt?: string | null;
}

export interface ImageStigBenchmark {
  benchmarkId: string;
  title: string;
  version: string;
  source: ScapSource | string;
  profileId: string;
  summary: ImageStigSummary;
  /** one page of rules (`page/pageSize/result/severity/q`) */
  rules: ScapRule[];
  /** assumed: rules matching the filters (falls back to `rules.length`) */
  rulesTotal: number;
  page: number;
  pageSize: number;
  /** assumed: `full` | `degraded` — rootfs extraction kept owner/mode/xattrs or not */
  rootfsFidelity?: string | null;
  /** assumed: why fidelity is degraded */
  rootfsWarnings?: string[];
  checkedAt?: string | null;
}

/** `GET /images/{id}/stig`. No benchmarks = no applicable benchmark (`reason` assumed). */
export interface ImageStig {
  benchmarks: ImageStigBenchmark[];
  /** evaluated | notApplicable | noContent | error | timeout | notEvaluated */
  status?: string | null;
  /** from `rootfs.fidelity` */
  rootfsFidelity?: string | null;
  /** from `rootfs.notes` / `droppedXattrs` */
  rootfsWarnings?: string[];
  reason?: string | null;
  /** `images.stig` brief (stale flag, error) */
  stig?: ImageStigBrief | null;
}

export interface ImageStigQuery {
  page?: number;
  pageSize?: number;
  /** comma-separated results */
  result?: string;
  /** comma-separated cat1|cat2|cat3 */
  severity?: string;
  q?: string;
  /** restrict the response to one benchmark (the UI doesn't send it: it keeps every sub-tab) */
  benchmark?: string;
}

/** `GET /stig/benchmarks` row and `/compliance/stig` `product[]` row. */
export interface StigBenchmark {
  id: string;
  title: string;
  version: string;
  source: ScapSource | string;
  profileId?: string | null;
  imagesEvaluated: number;
  pass: number;
  fail: number;
  notapplicable?: number;
  notchecked?: number;
  /** assumed: open rules (failing on ≥1 image) per category */
  cat1Open?: number;
  cat2Open?: number;
  cat3Open?: number;
}

export interface StigBenchmarkImage {
  imageId: string;
  ref: string;
  result?: ScapResult | string;
}

/** `GET /stig/benchmarks/{id}/rules` row. */
export interface StigBenchmarkRule {
  ruleId: string;
  stigId: string | null;
  cat: ScapCat;
  /** assumed */
  title?: string | null;
  failingImages: number;
  passingImages: number;
  /** images behind the counts: API `failing[]` (first 50), plus assumed `images[]` / `passing[]` */
  images: StigBenchmarkImage[];
  otherImages?: number;
  /** assumed */
  cci?: string[];
  fixText?: string | null;
}

/** `GET /compliance/stig`: the Kubernetes STIG list plus the §14 `product` rollup. */
export interface ComplianceStig {
  kubernetes: StigRule[];
  /** null = the API has no `product` section */
  product: StigBenchmark[] | null;
}

/** `scap` scanner `content[]` entry; `name` = title, else file. */
export interface ScapContentVersion {
  name: string;
  version: string | null;
  file?: string | null;
  title?: string | null;
  source?: string | null;
  sourceName?: string | null;
  benchmarkId?: string | null;
  fetchedAt?: string | null;
  sha256?: string | null;
  rules?: number | null;
}

/** `GET /stig/benchmarks/{id}/rules`: the rule rollup plus the benchmark row. */
export interface StigBenchmarkRules {
  benchmark: StigBenchmark | null;
  rules: StigBenchmarkRule[];
}
