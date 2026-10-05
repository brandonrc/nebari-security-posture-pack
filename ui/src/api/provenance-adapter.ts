/**
 * Maps a provenance-collector report (`GET /api/reports/{latest|filename}`) onto the shapes the
 * posture UI already renders — `ImageSummary.provenance`, `SupplyChainSummary`, `HelmRelease[]`,
 * `Namespace[]`, `ImageDetail` and `Me` — so the Images, Supply chain and image detail pages work
 * unchanged in provenance mode. The supply-chain score is computed client-side with
 * `lib/supply-chain.ts` (the collector doesn't score).
 *
 * "Check not run" vs "negative": the report omits `sbom` / `provenance` / `update` both when the
 * check found nothing and when it is disabled. A check counts as enabled for a report when any
 * record carries that object; then an image with a resolved digest and no object is a negative
 * (`hasSBOM: false`, up to date, …). Images whose digest couldn't be resolved never reached the
 * registry checks, so their missing objects stay "not checked". `signature` is absent only when
 * signature checks are disabled (schema), so it maps 1:1.
 */
import { useSyncExternalStore } from 'react';
import { gradeForScore } from '@/lib/scoring';
import { isMutableTag, supplyChainScore } from '@/lib/supply-chain';
import type { PcHelmRecord, PcImageRecord, PcMe, PcProvenanceReport, PcReportEntry, PcReportSummary, PcUpdateInfo } from './provenance-report';
import type {
  ContainerRef,
  HelmRelease,
  ImageDetail,
  ImageProvenance,
  ImageQuery,
  ImageSummary,
  Me,
  Namespace,
  Page,
  SeverityCounts,
  SupplyChainSummary,
  UpdateInfo,
} from './types';

/** `Me` plus the provenance dashboard's scan gate and feature flags. */
export interface ProvenanceMe extends Me {
  canRunScan: boolean;
  authEnabled: boolean;
  features: { timelineDeltas: boolean };
}

export interface ReportMeta {
  /** `null` = `provenance-latest.json` */
  filename: string | null;
  schemaVersion: string;
  generatedAt: string;
  collectorVersion: string;
  clusterName: string | null;
  namespacesScanned: string[];
  totalImages: number;
  /** the report's own summary (record-level counts, as the collector computed them) */
  summary: PcReportSummary | null;
  warnings: string[];
}

export interface AdaptedReport {
  meta: ReportMeta;
  images: ImageSummary[];
  details: Map<string, ImageDetail>;
  helmReleases: HelmRelease[];
  supplyChain: SupplyChainSummary;
  namespaces: Namespace[];
  /** which optional checks this report ran (see the module comment) */
  checks: { signature: boolean; sbom: boolean; provenance: boolean; update: boolean };
}

const ZERO: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0 };

/**
 * Where every schema field lands. The adapter test walks `report.schema.json` and fails when a
 * field is missing here, so a new collector field can't be dropped silently.
 */
export const SCHEMA_FIELD_MAP: Record<string, Record<string, string>> = {
  ProvenanceReport: {
    metadata: 'AdaptedReport.meta',
    images: 'AdaptedReport.images / details (grouped by image reference)',
    helmReleases: 'AdaptedReport.helmReleases',
    summary: 'meta.summary (supplyChain counts are recomputed per unique image)',
    warnings: 'meta.warnings; per-image ImageSummary.warnings when the entry names the image',
  },
  ReportMetadata: {
    schemaVersion: 'meta.schemaVersion',
    generatedAt: 'meta.generatedAt; ImageSummary.lastScannedAt; provenance.checkedAt',
    collectorVersion: 'meta.collectorVersion',
    clusterName: 'meta.clusterName',
    namespacesScanned: 'meta.namespacesScanned; AdaptedReport.namespaces',
  },
  ImageRecord: {
    image: 'ImageSummary.ref (+ registry/repository/tag parsed from it)',
    digest: 'ImageSummary.digest',
    namespace: 'ImageSummary.namespaces; ImageDetail.usedBy[].namespace',
    workload: 'ImageSummary.workloads (distinct); ImageDetail.usedBy[]',
    signature: 'provenance.signature',
    sbom: 'provenance.sbom',
    provenance: 'provenance.provenance',
    update: 'provenance.update',
  },
  WorkloadRef: { kind: 'usedBy[].kind', name: 'usedBy[].name' },
  SignatureInfo: { signed: 'signature.signed', verified: 'signature.verified', error: 'signature.error' },
  SBOMInfo: { hasSBOM: 'sbom.hasSBOM', format: 'sbom.format' },
  ProvenanceInfo: { hasProvenance: 'provenance.hasProvenance', predicateType: 'provenance.predicateType' },
  UpdateInfo: {
    currentTag: 'update.currentTag',
    latestInMajor: 'update.latestInMajor',
    newestAvailable: 'update.newestAvailable',
    updateAvailable: 'update.updateAvailable',
  },
  HelmRecord: {
    releaseName: 'HelmRelease.releaseName',
    namespace: 'HelmRelease.namespace',
    chart: 'HelmRelease.chart',
    version: 'HelmRelease.version',
    appVersion: 'HelmRelease.appVersion',
    status: 'HelmRelease.status',
    update: 'HelmRelease.update',
  },
  // The collector counts signed/SBOM/provenance/updates per container record but uniqueImages per
  // reference; the UI recomputes every count per unique image (same key) so percentages stay ≤ 100%.
  ReportSummary: {
    totalImages: 'meta.totalImages; Reports/Scans tables',
    uniqueImages: 'supplyChain.unique (recomputed); Reports/Scans tables',
    signedImages: 'supplyChain.signed (recomputed); Reports table',
    verifiedImages: 'supplyChain.verified (recomputed); Reports table',
    imagesWithSBOM: 'supplyChain.withSbom (recomputed); Reports table',
    imagesWithProvenance: 'supplyChain.withProvenance (recomputed); Reports table',
    imagesWithUpdates: 'supplyChain.withUpdates (recomputed); Reports table',
    totalHelmReleases: 'supplyChain.helmReleases (recomputed); Scans table',
    helmReleasesWithUpdates: 'supplyChain.helmWithUpdates (recomputed); Reports table',
  },
};

// ── image references ─────────────────────────────────────────────────────────

export interface ParsedRef {
  registry: string;
  repository: string;
  tag: string | null;
  /** digest pinned in the reference itself (`repo@sha256:…`) */
  pinned: string | null;
}

/** Docker-style reference parse: `busybox:1.36` → docker.io / library/busybox / 1.36. */
export function parseImageRef(ref: string): ParsedRef {
  let rest = ref.trim();
  let pinned: string | null = null;
  const at = rest.indexOf('@');
  if (at >= 0) {
    pinned = rest.slice(at + 1) || null;
    rest = rest.slice(0, at);
  }
  const slash = rest.indexOf('/');
  const first = slash >= 0 ? rest.slice(0, slash) : '';
  const hasRegistry = slash >= 0 && (first.includes('.') || first.includes(':') || first === 'localhost');
  const registry = hasRegistry ? first : 'docker.io';
  const path = hasRegistry ? rest.slice(slash + 1) : rest;
  const colon = path.lastIndexOf(':');
  const tag = colon >= 0 ? path.slice(colon + 1) || null : null;
  let repository = colon >= 0 ? path.slice(0, colon) : path;
  if (registry === 'docker.io' && !repository.includes('/')) repository = `library/${repository}`;
  return { registry, repository, tag, pinned };
}

/**
 * Per-unique-image id (URL segment): the reference as written in the pod spec — the collector's
 * own `uniqueImages` key, so the adapter's counts line up with the report summary.
 */
export function imageId(record: Pick<PcImageRecord, 'image'>): string {
  return record.image;
}

// ── mapping ──────────────────────────────────────────────────────────────────

function arr<T>(v: T[] | null | undefined): T[] {
  return Array.isArray(v) ? v : [];
}

function upToDate(currentTag: string): UpdateInfo {
  return { currentTag, updateAvailable: false };
}

function mapUpdate(u: PcUpdateInfo): UpdateInfo {
  return {
    currentTag: u.currentTag,
    latestInMajor: u.latestInMajor ?? null,
    newestAvailable: u.newestAvailable ?? null,
    updateAvailable: Boolean(u.updateAvailable),
  };
}

function mapProvenance(rec: PcImageRecord, checks: AdaptedReport['checks'], tag: string | null, checkedAt: string): ImageProvenance | null {
  const reached = Boolean(rec.digest);
  const p: ImageProvenance = { checkedAt };
  if (rec.signature) p.signature = { signed: Boolean(rec.signature.signed), verified: Boolean(rec.signature.verified), error: rec.signature.error ?? null };
  if (rec.sbom) p.sbom = { hasSBOM: Boolean(rec.sbom.hasSBOM), format: rec.sbom.format ?? null };
  else if (checks.sbom && reached) p.sbom = { hasSBOM: false };
  if (rec.provenance) p.provenance = { hasProvenance: Boolean(rec.provenance.hasProvenance), predicateType: rec.provenance.predicateType ?? null };
  else if (checks.provenance && reached) p.provenance = { hasProvenance: false };
  if (rec.update) p.update = mapUpdate(rec.update);
  else if (checks.update && reached && tag) p.update = upToDate(tag);
  if (!p.signature && !p.sbom && !p.provenance && !p.update) return null;
  p.mutableTag = !rec.image.includes('@') && isMutableTag(tag);
  const sc = supplyChainScore(p, { tag });
  if (sc) {
    p.score = sc.score;
    p.grade = sc.grade;
    p.deductions = sc.deductions;
  }
  return p;
}

function mapHelm(h: PcHelmRecord, updatesChecked: boolean): HelmRelease {
  return {
    releaseName: h.releaseName,
    namespace: h.namespace,
    chart: h.chart,
    version: h.version,
    appVersion: h.appVersion ?? '',
    status: h.status,
    update: h.update ? mapUpdate(h.update) : updatesChecked ? upToDate(h.version) : null,
  };
}

/** Container-weighted mean of the per-image supply-chain scores (null when nothing was checked). */
export function weightedScore(images: ImageSummary[]): number | null {
  let total = 0;
  let weight = 0;
  for (const i of images) {
    const s = i.provenance?.score;
    if (typeof s !== 'number') continue;
    const w = Math.max(1, i.containers);
    total += s * w;
    weight += w;
  }
  return weight ? Math.round((total / weight) * 10) / 10 : null;
}

export function adaptReport(raw: PcProvenanceReport, filename: string | null = null): AdaptedReport {
  const records = arr(raw?.images);
  const helm = arr(raw?.helmReleases);
  const warnings = arr(raw?.warnings);
  const md = raw?.metadata ?? ({} as PcProvenanceReport['metadata']);
  const generatedAt = md.generatedAt ?? '';
  const checks = {
    signature: records.some((r) => r.signature),
    sbom: records.some((r) => r.sbom),
    provenance: records.some((r) => r.provenance),
    update: records.some((r) => r.update) || helm.some((h) => h.update),
  };

  const groups = new Map<string, PcImageRecord[]>();
  for (const r of records) {
    const id = imageId(r);
    groups.set(id, [...(groups.get(id) ?? []), r]);
  }

  const images: ImageSummary[] = [];
  const details = new Map<string, ImageDetail>();
  for (const [id, recs] of groups) {
    const first = recs[0];
    const ref = parseImageRef(first.image);
    const namespaces = [...new Set(recs.map((r) => r.namespace))].sort();
    const usedBy: ContainerRef[] = [];
    const seen = new Set<string>();
    for (const r of recs) {
      const key = `${r.namespace}/${r.workload?.kind}/${r.workload?.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      usedBy.push({ namespace: r.namespace, kind: r.workload?.kind ?? '', name: r.workload?.name ?? '', container: '', running: true });
    }
    const summary: ImageSummary = {
      id,
      ref: first.image,
      registry: ref.registry,
      repository: ref.repository,
      tag: ref.tag,
      digest: first.digest ?? ref.pinned ?? null,
      score: null,
      grade: '?',
      counts: { ...ZERO },
      fixable: {},
      scanners: {},
      agreementIndex: null,
      namespaces,
      workloads: usedBy.length,
      containers: recs.length,
      running: true,
      current: true,
      lastScannedAt: generatedAt || null,
      mirrored: false,
      warnings: warnings.filter((w) => w.includes(first.image)),
      provenance: mapProvenance(first, checks, ref.tag, generatedAt),
    };
    images.push(summary);
    details.set(id, { ...summary, findings: [], findingsTotal: 0, usedBy, scans: [], postureFindings: [] });
  }

  const s = raw?.summary ?? null;
  const helmReleases = helm.map((h) => mapHelm(h, checks.update));
  const score = weightedScore(images);
  const count = (pred: (p: ImageProvenance) => unknown) => images.filter((i) => i.provenance && pred(i.provenance)).length;
  const supplyChain: SupplyChainSummary = {
    signed: count((p) => p.signature?.signed),
    verified: count((p) => p.signature?.verified),
    withSbom: count((p) => p.sbom?.hasSBOM),
    withProvenance: count((p) => p.provenance?.hasProvenance),
    withUpdates: count((p) => p.update?.updateAvailable),
    unique: images.length,
    helmReleases: helmReleases.length,
    helmWithUpdates: helmReleases.filter((h) => h.update?.updateAvailable).length,
    score,
    grade: gradeForScore(score),
    stale: 0,
    includeStale: false,
  };

  const nsNames = [...new Set([...arr(md.namespacesScanned), ...records.map((r) => r.namespace)])].sort();
  const namespaces: Namespace[] = nsNames.map((name) => {
    const inNs = records.filter((r) => r.namespace === name);
    return {
      name,
      pack: null,
      managed: false,
      score: null,
      grade: '?',
      workloads: new Set(inNs.map((r) => `${r.workload?.kind}/${r.workload?.name}`)).size,
      images: new Set(inNs.map(imageId)).size,
      counts: { ...ZERO },
      posture: { passed: 0, failed: 0 },
    };
  });

  return {
    meta: {
      filename,
      schemaVersion: md.schemaVersion ?? '1.0.0',
      generatedAt,
      collectorVersion: md.collectorVersion ?? '',
      clusterName: md.clusterName || null,
      namespacesScanned: arr(md.namespacesScanned),
      totalImages: s?.totalImages ?? records.length,
      summary: s,
      warnings,
    },
    images,
    details,
    helmReleases,
    supplyChain,
    namespaces,
    checks,
  };
}

/** Client-side filter / sort / page for `GET /images` semantics. */
export function queryImages(report: AdaptedReport, q: ImageQuery = {}): Page<ImageSummary> {
  const needle = q.q?.trim().toLowerCase();
  let items = report.images.filter((i) => {
    if (q.namespace && !i.namespaces.includes(q.namespace)) return false;
    if (q.grade && (i.provenance?.grade ?? '?') !== q.grade) return false;
    if (needle && !i.ref.toLowerCase().includes(needle) && !(i.digest ?? '').toLowerCase().includes(needle)) return false;
    return true;
  });
  const dir = q.order === 'desc' ? -1 : 1;
  const key = q.sort ?? 'ref';
  const val = (i: ImageSummary): number | string => {
    if (key === 'score') return i.provenance?.score ?? Number.POSITIVE_INFINITY;
    if (key === 'workloads') return i.workloads;
    if (key === 'namespace') return i.namespaces[0] ?? '';
    return i.ref;
  };
  items = [...items].sort((a, b) => {
    const x = val(a);
    const y = val(b);
    const c = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y));
    return c * dir || a.ref.localeCompare(b.ref);
  });
  const pageSize = Math.max(1, q.pageSize ?? 50);
  const page = Math.max(1, q.page ?? 1);
  return { items: items.slice((page - 1) * pageSize, page * pageSize), total: items.length, page, pageSize };
}

export function adaptMe(me: Partial<PcMe> | null | undefined, user: { name: string; email: string } | null): ProvenanceMe {
  const email = me?.email || user?.email || '';
  const canRunScan = Boolean(me?.canRunScan);
  return {
    username: user?.name || email || (me?.authEnabled ? 'Signed in' : 'Anonymous'),
    email,
    groups: Array.isArray(me?.groups) ? me.groups : [],
    // read access is any authenticated user; the admin gate only applies to Run scan
    isAdmin: canRunScan,
    canRunScan,
    authEnabled: Boolean(me?.authEnabled),
    features: { timelineDeltas: Boolean(me?.features?.timelineDeltas) },
  };
}

/** Per-entry unique-image delta vs the next-older report (the old UI's timeline badge). */
export function reportDeltas(entries: PcReportEntry[]): Map<string, number | null> {
  const out = new Map<string, number | null>();
  entries.forEach((e, i) => {
    const older = entries[i + 1];
    out.set(e.filename, older ? (e.summary?.uniqueImages ?? 0) - (older.summary?.uniqueImages ?? 0) : null);
  });
  return out;
}

// ── active dataset ("View report N") ─────────────────────────────────────────

let dataset: string | null = null;
const listeners = new Set<() => void>();

/** The report being viewed: a `/api/reports` filename, or null for `latest`. */
export function getDataset(): string | null {
  return dataset;
}

export function setDataset(filename: string | null): void {
  if (dataset === filename) return;
  dataset = filename;
  for (const l of listeners) l();
}

export function useDataset(): string | null {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => dataset,
    () => dataset,
  );
}

// ── report cache ─────────────────────────────────────────────────────────────

const LATEST_TTL_MS = 15_000;
const cache = new Map<string, { at: number; value: Promise<AdaptedReport> }>();

/**
 * The active dataset, adapted. Timestamped reports are immutable and cached for the session;
 * `latest` is re-read after 15 s. `fetchReport` is the authenticated `GET /api/reports/{name}`.
 */
export function loadDataset(fetchReport: (name: string) => Promise<PcProvenanceReport>, filename: string | null = dataset): Promise<AdaptedReport> {
  const key = filename ?? 'latest';
  const hit = cache.get(key);
  if (hit && (filename !== null || Date.now() - hit.at < LATEST_TTL_MS)) return hit.value;
  const value = fetchReport(key).then((r) => adaptReport(r, filename));
  value.catch(() => cache.delete(key));
  cache.set(key, { at: Date.now(), value });
  return value;
}

export function clearReportCache(): void {
  cache.clear();
}

export function resetProvenanceState(): void {
  cache.clear();
  dataset = null;
  for (const l of listeners) l();
}
