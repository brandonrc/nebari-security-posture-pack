/**
 * Defensive defaults for API responses (quality review M5). The pages trust the DESIGN §5
 * shapes; during a rolling upgrade (new UI, old API) or from a misbehaving proxy a body can be
 * `{}`, `[]`, `null` or have `null` arrays. These fill the containers pages iterate over so a
 * malformed body renders empty states instead of a crash. Scalars stay as served (or null).
 */
import type {
  CheckDetail,
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
    scanners: arr(r.scanners),
    trend: arr(r.trend),
    topRisks: arr(r.topRisks),
    checks: { passed: 0, failed: 0, total: 0, ...obj(r.checks) } as Summary['checks'],
    warnings: arr(r.warnings),
    lastScan: (r.lastScan as Summary['lastScan'] | undefined) ?? null,
  };
}

export function imageSummary(raw: unknown): ImageSummary {
  const r = obj(raw);
  return {
    ...(r as unknown as ImageSummary),
    id: str(r.id),
    ref: str(r.ref),
    registry: str(r.registry),
    repository: str(r.repository),
    grade: (r.grade as ImageSummary['grade'] | undefined) ?? '?',
    counts: counts(r.counts),
    fixable: obj(r.fixable) as ImageSummary['fixable'],
    scanners: obj(r.scanners) as ImageSummary['scanners'],
    namespaces: arr(r.namespaces),
    warnings: arr(r.warnings),
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
