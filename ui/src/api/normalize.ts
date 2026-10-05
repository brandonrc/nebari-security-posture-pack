/**
 * Defensive defaults for API responses (quality review M5). The pages trust the DESIGN §5
 * shapes; during a rolling upgrade (new UI, old API) or from a misbehaving proxy a body can be
 * `{}`, `[]`, `null` or have `null` arrays. These fill the containers pages iterate over so a
 * malformed body renders empty states instead of a crash. Scalars stay as served (or null).
 */
import { normCat } from '@/lib/stig';
import type {
  CheckDetail,
  ComplianceStig,
  ImageStig,
  ImageStigBenchmark,
  ImageStigSummary,
  ScapContentVersion,
  ScapRule,
  StigBenchmark,
  StigBenchmarkImage,
  StigBenchmarkRule,
  StigBenchmarkRules,
  StigRollup,
  StigRule,
  ImageDetail,
  ImageSummary,
  Page,
  SeverityCounts,
  Settings,
  Summary,
  SupplyChainSummary,
  VulnDetail,
  VulnList,
  VulnSummary,
} from './types';

type Loose = Record<string, unknown>;

export function obj(value: unknown): Loose {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Loose) : {};
}

export function arr<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function str(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

/** Ids may be strings or (posture API) integers. */
export function idStr(value: unknown): string {
  return typeof value === 'string' ? value : typeof value === 'number' && Number.isFinite(value) ? String(value) : '';
}

function num(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

export function counts(value: unknown): SeverityCounts {
  const c = obj(value);
  return {
    critical: num(c.critical),
    high: num(c.high),
    medium: num(c.medium),
    low: num(c.low),
    negligible: num(c.negligible),
    unknown: num(c.unknown),
  };
}

export function summary(raw: unknown): Summary {
  const r = obj(raw);
  return {
    ...(r as unknown as Summary),
    score: (r.score as number | null | undefined) ?? null,
    grade: (r.grade as Summary['grade'] | undefined) ?? '?',
    counts: counts(r.counts),
    fixable: obj(r.fixable) as Summary['fixable'],
    images: { total: 0, scanned: 0, failed: 0, ...obj(r.images) } as Summary['images'],
    scanners: arr<unknown>(r.scanners).map((x) => scanner(x)),
    trend: arr(r.trend),
    topRisks: arr(r.topRisks),
    checks: { passed: 0, failed: 0, total: 0, ...obj(r.checks) } as Summary['checks'],
    warnings: arr(r.warnings),
    lastScan: (r.lastScan as Summary['lastScan'] | undefined) ?? null,
    stig: r.stig === undefined ? undefined : r.stig === null || typeof r.stig !== 'object' ? null : stigRollup(r.stig),
  };
}

function stigRollup(raw: unknown): StigRollup {
  const r = obj(raw);
  return {
    evaluated: num(r.evaluated),
    pass: num(r.pass),
    fail: num(r.fail),
    cat1Open: num(r.cat1Open),
    cat2Open: num(r.cat2Open),
    cat3Open: num(r.cat3Open),
    coverage: typeof r.coverage === 'number' && Number.isFinite(r.coverage) ? r.coverage : null,
    notApplicable: optNum(r.notApplicable),
    noContent: optNum(r.noContent),
    errors: optNum(r.errors),
    pending: optNum(r.pending),
    images: optNum(r.images),
    score: typeof r.score === 'number' && Number.isFinite(r.score) ? r.score : null,
  };
}

export function imageSummary(raw: unknown): ImageSummary {
  const r = obj(raw);
  return {
    ...(r as unknown as ImageSummary),
    id: idStr(r.id),
    ref: str(r.ref),
    registry: str(r.registry),
    repository: str(r.repository),
    grade: (r.grade as ImageSummary['grade'] | undefined) ?? '?',
    counts: counts(r.counts),
    fixable: obj(r.fixable) as ImageSummary['fixable'],
    scanners: obj(r.scanners) as ImageSummary['scanners'],
    namespaces: arr(r.namespaces),
    warnings: arr(r.warnings),
    ...('stig' in r ? { stig: r.stig && typeof r.stig === 'object' && !Array.isArray(r.stig) ? (r.stig as ImageSummary['stig']) : null } : {}),
  };
}

export function page<T>(raw: unknown, item: (x: unknown) => T): Page<T> {
  const r = obj(raw);
  const items = arr<unknown>(Array.isArray(raw) ? raw : r.items).map(item);
  return { ...(r as unknown as Page<T>), items, total: num(r.total, items.length), page: num(r.page, 1), pageSize: num(r.pageSize, items.length) };
}

export function imageDetail(raw: unknown): ImageDetail {
  const r = obj(raw);
  return {
    ...(r as unknown as ImageDetail),
    ...imageSummary(r),
    findings: arr(r.findings),
    usedBy: arr(r.usedBy),
    scans: arr(r.scans),
    postureFindings: arr(r.postureFindings),
  };
}

function vulnSummary(raw: unknown): VulnSummary {
  const r = obj(raw);
  return { ...(r as unknown as VulnSummary), scanners: arr(r.scanners), controls: arr(r.controls) };
}

export function vulnList(raw: unknown): VulnList {
  const p = page(raw, vulnSummary);
  return { ...p };
}

export function vulnDetail(raw: unknown): VulnDetail {
  const r = obj(raw);
  return { ...(r as unknown as VulnDetail), ...vulnSummary(r), images: arr(r.images) };
}

export function checkDetail(raw: unknown): CheckDetail {
  const r = obj(raw);
  return { ...(r as unknown as CheckDetail), results: arr(r.results), controls: arr(r.controls), passed: num(r.passed), failed: num(r.failed) };
}

export function supplyChain(raw: unknown): SupplyChainSummary {
  const r = obj(raw);
  const n = (k: string) => num(r[k]);
  return {
    ...(r as unknown as SupplyChainSummary),
    signed: n('signed'),
    verified: n('verified'),
    withSbom: n('withSbom'),
    withProvenance: n('withProvenance'),
    withUpdates: n('withUpdates'),
    unique: n('unique'),
    helmReleases: n('helmReleases'),
    helmWithUpdates: n('helmWithUpdates'),
    score: (r.score as number | null | undefined) ?? null,
    grade: (r.grade as SupplyChainSummary['grade'] | undefined) ?? '?',
  };
}

export function settings(raw: unknown): Settings {
  const r = obj(raw);
  const out: Settings = {
    ...(r as unknown as Settings),
    excludedNamespaces: arr(r.excludedNamespaces),
    adminGroups: arr(r.adminGroups),
    scanners: { trivy: false, grype: false, clair: false, ...obj(r.scanners) } as Settings['scanners'],
  };
  if (r.reports !== undefined) out.reports = { ...obj(r.reports), autoGenerate: arr(obj(r.reports).autoGenerate) };
  return out;
}

// ── §14 SCAP ─────────────────────────────────────────────────────────────────

function optNum(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function strList(value: unknown): string[] {
  if (typeof value === 'string') return value ? value.split(/[,\s]+/).filter(Boolean) : [];
  return arr<unknown>(value).filter((x): x is string => typeof x === 'string');
}

export function scapRule(raw: unknown): ScapRule {
  const r = obj(raw);
  return {
    ...(r as unknown as ScapRule),
    ruleId: str(r.ruleId),
    stigId: typeof r.stigId === 'string' && r.stigId ? r.stigId : null,
    cci: strList(r.cci),
    severity: normCat(r.severity ?? r.cat),
    result: str(r.result, 'unknown'),
    title: str(r.title, str(r.ruleId)),
    fixText: typeof r.fixText === 'string' ? r.fixText : null,
  };
}

function stigSummary(raw: unknown): ImageStigSummary {
  const r = obj(raw);
  return {
    ...(r as unknown as ImageStigSummary),
    pass: num(r.pass),
    fail: num(r.fail),
    notapplicable: num(r.notapplicable),
    notchecked: num(r.notchecked),
    error: num(r.error),
    score: typeof r.score === 'number' && Number.isFinite(r.score) ? r.score : null,
    cat1Open: optNum(r.cat1Open),
    cat2Open: optNum(r.cat2Open),
    cat3Open: optNum(r.cat3Open),
    rootfsFidelity: typeof r.rootfsFidelity === 'string' ? r.rootfsFidelity : null,
    evaluatedAt: typeof r.evaluatedAt === 'string' ? r.evaluatedAt : null,
  };
}

function imageStigBenchmark(raw: unknown): ImageStigBenchmark {
  const r = obj(raw);
  const rules = arr<unknown>(Array.isArray(r.rules) ? r.rules : obj(r.rules).items).map(scapRule);
  const rulesPage = obj(r.rules);
  const summary = stigSummary(r.summary);
  return {
    ...(r as unknown as ImageStigBenchmark),
    benchmarkId: str(r.benchmarkId, str(r.id)),
    title: str(r.title, str(r.benchmarkId, str(r.id))),
    version: str(r.version),
    source: str(r.source),
    profileId: str(r.profileId, str(obj(r.summary).profile)),
    summary,
    rules,
    rulesTotal: num(r.rulesTotal, num(rulesPage.total, rules.length)),
    page: num(r.page, num(rulesPage.page, 1)),
    pageSize: num(r.pageSize, num(rulesPage.pageSize, rules.length)),
    rootfsFidelity: typeof r.rootfsFidelity === 'string' ? r.rootfsFidelity : summary.rootfsFidelity,
    rootfsWarnings: strList(r.rootfsWarnings),
    checkedAt: typeof r.checkedAt === 'string' ? r.checkedAt : summary.evaluatedAt,
  };
}

/** `rootfs` (`RootfsResult.as_dict`) → warnings shown with a degraded extraction. */
function rootfsWarnings(raw: unknown): string[] {
  const r = obj(raw);
  const out = strList(r.notes);
  const n = (k: string) => num(r[k]);
  if (n('droppedXattrs')) out.push(`${n('droppedXattrs')} extended attributes could not be restored`);
  if (n('skippedDevices')) out.push(`${n('skippedDevices')} device files skipped`);
  if (n('unsafeEntries')) out.push(`${n('unsafeEntries')} unsafe layer entries refused`);
  return out;
}

export function imageStig(raw: unknown): ImageStig {
  const r = obj(raw);
  const rootfs = obj(r.rootfs);
  const fidelity = typeof r.rootfsFidelity === 'string' ? r.rootfsFidelity : typeof rootfs.fidelity === 'string' ? rootfs.fidelity : null;
  return {
    ...(r as unknown as ImageStig),
    benchmarks: arr<unknown>(Array.isArray(raw) ? raw : r.benchmarks).map(imageStigBenchmark),
    status: typeof r.status === 'string' ? r.status : null,
    rootfsFidelity: fidelity,
    rootfsWarnings: [...strList(r.rootfsWarnings), ...rootfsWarnings(r.rootfs)],
    reason: typeof r.reason === 'string' ? r.reason : null,
  };
}

export function stigBenchmark(raw: unknown): StigBenchmark {
  const r = obj(raw);
  const id = idStr(r.id) || idStr(r.benchmarkId);
  return {
    ...(r as unknown as StigBenchmark),
    id,
    title: str(r.title, id),
    version: str(r.version),
    source: str(r.source),
    imagesEvaluated: num(r.imagesEvaluated),
    pass: num(r.pass),
    fail: num(r.fail),
    notapplicable: optNum(r.notapplicable),
    notchecked: optNum(r.notchecked),
    cat1Open: optNum(r.cat1Open),
    cat2Open: optNum(r.cat2Open),
    cat3Open: optNum(r.cat3Open),
  };
}

function benchmarkImage(raw: unknown, result?: string): StigBenchmarkImage | null {
  if (typeof raw === 'string' || typeof raw === 'number') return { imageId: idStr(raw), ref: idStr(raw), result };
  const r = obj(raw);
  const imageId = idStr(r.imageId) || idStr(r.id);
  if (!imageId) return null;
  return { ...(r as unknown as StigBenchmarkImage), imageId, ref: str(r.ref, imageId), result: typeof r.result === 'string' ? r.result : result };
}

export function stigBenchmarkRule(raw: unknown): StigBenchmarkRule {
  const r = obj(raw);
  const listed = [
    ...arr<unknown>(r.images).map((x) => benchmarkImage(x)),
    ...arr<unknown>(r.failing).map((x) => benchmarkImage(x, 'fail')),
    ...arr<unknown>(r.passing).map((x) => benchmarkImage(x, 'pass')),
    ...arr<unknown>(r.failingImages).map((x) => benchmarkImage(x, 'fail')),
    ...arr<unknown>(r.passingImages).map((x) => benchmarkImage(x, 'pass')),
  ].filter((x): x is StigBenchmarkImage => x !== null);
  const count = (key: 'failingImages' | 'passingImages', result: string) =>
    Array.isArray(r[key]) ? (r[key] as unknown[]).length : num(r[key], listed.filter((i) => i.result === result).length);
  return {
    ...(r as unknown as StigBenchmarkRule),
    ruleId: str(r.ruleId),
    stigId: typeof r.stigId === 'string' && r.stigId ? r.stigId : null,
    cat: normCat(r.cat ?? r.severity),
    title: typeof r.title === 'string' ? r.title : null,
    failingImages: count('failingImages', 'fail'),
    passingImages: count('passingImages', 'pass'),
    images: listed,
    cci: strList(r.cci),
    fixText: typeof r.fixText === 'string' ? r.fixText : null,
    otherImages: optNum(r.otherImages),
  };
}

/** `GET /stig/benchmarks/{id}/rules`: `{benchmark, items, total, page, pageSize}` or a bare list. */
export function stigBenchmarkRules(raw: unknown): StigBenchmarkRules & { total: number } {
  const r = obj(raw);
  const rules = arr<unknown>(Array.isArray(raw) ? raw : r.items).map(stigBenchmarkRule);
  const b = r.benchmark && typeof r.benchmark === 'object' ? stigBenchmark(r.benchmark) : null;
  return { benchmark: b && b.id ? b : null, rules, total: num(r.total, rules.length) };
}

function contentVersion(raw: unknown): ScapContentVersion {
  const r = obj(raw);
  const title = typeof r.title === 'string' ? r.title : null;
  const file = typeof r.file === 'string' ? r.file : null;
  return {
    ...(r as unknown as ScapContentVersion),
    name: str(r.name) || title || file || idStr(r.benchmarkId),
    version: typeof r.version === 'string' ? r.version : null,
  };
}

/** `GET /scanners` row; the `scap` entry's `content[]` becomes `contentVersions`. */
export function scanner<T extends { contentVersions?: ScapContentVersion[] }>(raw: unknown): T {
  const r = obj(raw);
  const content = Array.isArray(r.contentVersions) ? r.contentVersions : r.content;
  return { ...(r as unknown as T), contentVersions: arr<unknown>(content).map(contentVersion) };
}

/** `/compliance/stig`: a bare Kubernetes rule list (pre-§14) or `{items|kubernetes|rules, product}`. */
export function complianceStig(raw: unknown): ComplianceStig {
  if (Array.isArray(raw)) return { kubernetes: raw as StigRule[], product: null };
  const r = obj(raw);
  const k8s = r.kubernetes ?? r.items ?? r.rules;
  const kubernetes = arr<StigRule>(Array.isArray(k8s) ? k8s : obj(k8s).items ?? obj(k8s).rules);
  const p = r.product;
  // the API serves `product: {benchmarks: [...], ...summary}`; a bare list or `{items}` also works
  const productList = Array.isArray(p) ? p : p && typeof p === 'object' ? (obj(p).benchmarks ?? obj(p).items) : undefined;
  return { kubernetes, product: Array.isArray(productList) ? productList.map(stigBenchmark) : null };
}
