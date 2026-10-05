import { delay, http, HttpResponse } from 'msw';
import type { Finding, Grade, ImageDetail, ImageSummary, Report, ReportCreate, Scan, Settings, Severity, VulnSummary } from '@/api/types';
import { SCANNERS } from '@/api/types';
import { complianceTotals, inBaseline, rollupFamilies } from '@/lib/controls';
import { gradeRank, severityRank } from '@/lib/scoring';
import {
  buildSummary,
  checkDetailFor,
  checks,
  controlCoverage,
  defaultSettings,
  images,
  me,
  namespaces,
  reports as seedReports,
  reportTypes,
  scanDetail,
  scannerHealth,
  scans as seedScans,
  stigRules,
  supplyChainSummary,
  vulnIndex,
  workloads,
} from './fixtures';
import { assertions, resetAssertionRun, setAssertionRunAt } from './controls';
import { helmReleases } from './provenance';
import { defaultScapSettings, imageStigBrief, imageStigResponse, scapScannerHealth, stigBenchmarkCatalogue, stigBenchmarkRollup, stigBenchmarkRules, stigRollup } from './scap';

/**
 * MSW handlers mirroring DESIGN §5/§11. Mutable state (scans, reports,
 * settings) lives in module scope so the demo feels live: a manual scan
 * progresses over ~30s, reports finish a few seconds after creation.
 */
const API = '*/api/v1';
const SCAN_DURATION_MS = 30_000;
const REPORT_DURATION_MS = 5_000;
const ASSERTION_RUN_MS = 4_000;
let assertionRunStarted: number | null = null;

/** The engine "finishes" ASSERTION_RUN_MS after POST /compliance/assertions/run. */
function settleAssertionRun() {
  if (assertionRunStarted !== null && Date.now() - assertionRunStarted >= ASSERTION_RUN_MS) {
    setAssertionRunAt(assertionRunStarted + ASSERTION_RUN_MS);
    assertionRunStarted = null;
  }
}

const seedSettings = (): Settings => ({ ...structuredClone(defaultSettings), scanners: { ...defaultSettings.scanners, scap: true }, scap: structuredClone(defaultScapSettings) });
let settings: Settings = seedSettings();
const scans: Scan[] = structuredClone(seedScans);
const reports: Report[] = structuredClone(seedReports);
const reportStarted = new Map<string, number>([['rpt-0007', Date.now()]]);
const scanStarted = new Map<string, number>();
const cancelled = new Set<string>();

export function resetMockState() {
  settings = seedSettings();
  scans.splice(0, scans.length, ...structuredClone(seedScans));
  reports.splice(0, reports.length, ...structuredClone(seedReports));
  reportStarted.clear();
  scanStarted.clear();
  cancelled.clear();
  assertionRunStarted = null;
  resetAssertionRun();
}

/** Optional auth simulation: `?mockAuth=401|403` on the page URL. */
function authFailure() {
  if (typeof window === 'undefined' || !window.location) return null;
  const mode = new URLSearchParams(window.location.search).get('mockAuth');
  if (mode === '401') return HttpResponse.json({ detail: 'not authenticated' }, { status: 401 });
  if (mode === '403') return HttpResponse.json({ detail: 'admin group required' }, { status: 403 });
  return null;
}

const latency = () => delay(typeof window === 'undefined' ? 0 : 150 + Math.random() * 250);

function advanceScan(scan: Scan) {
  const started = scanStarted.get(String(scan.id));
  if (started === undefined || scan.status === 'done' || scan.status === 'cancelled' || scan.status === 'failed') return scan;
  const elapsed = Date.now() - started;
  if (cancelled.has(String(scan.id))) {
    scan.status = 'cancelled';
    scan.finishedAt = new Date().toISOString();
    return scan;
  }
  if (elapsed < 2_000) {
    scan.status = 'queued';
    return scan;
  }
  scan.status = 'running';
  scan.startedAt = scan.startedAt ?? new Date(started + 2_000).toISOString();
  const frac = Math.min(1, (elapsed - 2_000) / SCAN_DURATION_MS);
  scan.imagesDone = Math.floor(frac * scan.imagesTotal);
  scan.imagesFailed = scan.imagesDone >= scan.imagesTotal ? 1 : 0;
  if (frac >= 1) {
    const summary = buildSummary();
    scan.status = 'done';
    scan.finishedAt = new Date().toISOString();
    scan.score = summary.score;
    scan.grade = summary.grade;
  }
  return scan;
}

function advanceReport(report: Report) {
  const started = reportStarted.get(String(report.id));
  if (started === undefined || report.status === 'done' || report.status === 'failed') return report;
  const elapsed = Date.now() - started;
  if (elapsed < 1_000) report.status = 'queued';
  else if (elapsed < REPORT_DURATION_MS) report.status = 'running';
  else {
    report.status = 'done';
    report.sizeBytes = 12_000 + Math.floor(Math.random() * 200_000);
    const scope = report.scope.kind === 'cluster' ? '' : `-${(report.scope.name ?? '').split('/').pop()}`;
    report.filename = `${settings.systemName ?? 'cluster'}${scope}-${report.type}-scan${report.scanId}.${report.format}`;
  }
  return report;
}

function sortImages(items: ImageSummary[], sort: string, order: 'asc' | 'desc') {
  const dir = order === 'asc' ? 1 : -1;
  const key = (i: ImageSummary): number | string => {
    switch (sort) {
      case 'ref':
        return i.ref;
      case 'grade':
        return gradeRank(i.grade);
      case 'critical':
        return i.counts.critical;
      case 'high':
        return i.counts.high;
      case 'agreement':
        return i.agreementIndex ?? -1;
      case 'workloads':
        return i.workloads;
      case 'lastScannedAt':
        return i.lastScannedAt ?? '';
      case 'stig':
        return i.stig?.score ?? -1;
      default:
        return i.score ?? -1;
    }
  };
  return [...items].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    return (ka < kb ? -1 : ka > kb ? 1 : 0) * dir;
  });
}

function summaryOf({ findings: _f, usedBy: _u, scans: _s, postureFindings: _p, ...rest }: (typeof images)[number]): ImageSummary {
  return { ...rest, stig: imageStigBrief(rest.id) };
}

const UNPAGED_FINDINGS_LIMIT = 500;

/**
 * `GET /images/{id}` findings paging, mirroring api/src/posture/routers/images.py
 * `findings_page`: filter (severity, q, fixable, disagree), sort with the same
 * tie-breaks, slice `page`/`pageSize` (max 500), and summarise the filtered set.
 * Without `page` the first 500 come back with `truncated` when there are more.
 */
export function imageWithFindingsPage(image: ImageDetail, params: URLSearchParams): ImageDetail {
  const all = image.findings;
  const okScanners = SCANNERS.filter((s) => image.scanners[s]?.status === 'ok').length;
  const sevs = params.get('severity')?.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
  const q = params.get('q')?.toLowerCase();
  const fixable = params.get('fixable');
  const disagree = params.get('disagree') === 'true';
  const filtered = all.filter(
    (f) =>
      (!sevs?.length || sevs.includes(f.severity)) &&
      (!q || f.vulnId.toLowerCase().includes(q) || f.package.toLowerCase().includes(q) || (f.title ?? '').toLowerCase().includes(q)) &&
      (fixable === null || f.fixable === (fixable === 'true')) &&
      (!disagree || f.scanners.length < okScanners),
  );
  const sort = params.get('sort') ?? 'severity';
  const dir = (params.get('order') ?? 'desc').toLowerCase() === 'asc' ? 1 : -1;
  const keys: Record<string, (f: Finding) => Array<number | string>> = {
    severity: (f) => [severityRank(f.severity), f.cvss ?? 0],
    cvss: (f) => [f.cvss ?? 0, severityRank(f.severity)],
    vulnId: (f) => [f.vulnId],
    package: (f) => [f.package],
    agreement: (f) => [f.scanners.length, severityRank(f.severity)],
    firstSeenAt: (f) => [f.firstSeenAt ?? ''],
  };
  const key = keys[sort] ?? keys.severity;
  const cmp = (a: number | string, b: number | string) => (typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b)));
  const sorted = [...filtered].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    for (let i = 0; i < ka.length; i++) {
      const c = cmp(ka[i], kb[i]);
      if (c) return c * dir;
    }
    return a.vulnId.localeCompare(b.vulnId) || a.package.localeCompare(b.package);
  });
  const pageParam = params.get('page');
  const page = pageParam === null ? null : Math.max(1, Number(pageParam) || 1);
  const pageSize = Math.min(500, Math.max(1, Number(params.get('pageSize') ?? 50) || 50));
  const size = page === null ? UNPAGED_FINDINGS_LIMIT : pageSize;
  const start = page === null ? 0 : (page - 1) * pageSize;
  const bySeverity = Object.fromEntries((['critical', 'high', 'medium', 'low', 'negligible', 'unknown'] as Severity[]).map((s) => [s, filtered.filter((f) => f.severity === s).length])) as Record<Severity, number>;
  return {
    ...image,
    findings: sorted.slice(start, start + size),
    findingsTotal: filtered.length,
    findingsPage: page ?? 1,
    findingsPageSize: size,
    truncated: page === null && filtered.length > UNPAGED_FINDINGS_LIMIT,
    findingsSummary: {
      total: all.length,
      filtered: filtered.length,
      bySeverity,
      fixable: filtered.filter((f) => f.fixable).length,
      flaggedByAll: okScanners > 1 ? filtered.filter((f) => f.scanners.length >= okScanners).length : 0,
      scannersOk: okScanners,
    },
  };
}

export const handlers = [
  http.all(`${API}/*`, async () => {
    await latency();
    return authFailure() ?? undefined;
  }),

  http.get(`${API}/me`, () => HttpResponse.json(me)),

  http.get(`${API}/summary`, () => {
    const summary = buildSummary();
    // like the API: `stig` rollup on /summary; the `scap` scanner is only listed by /scanners
    summary.stig = stigRollup();
    const latest = scans[scans.length - 1];
    advanceScan(latest);
    summary.lastScan = {
      id: latest.id,
      status: latest.status,
      startedAt: latest.startedAt,
      finishedAt: latest.finishedAt,
      imagesTotal: latest.imagesTotal,
      imagesDone: latest.imagesDone,
      imagesFailed: latest.imagesFailed,
    };
    return HttpResponse.json(summary);
  }),

  http.get(`${API}/images`, ({ request }) => {
    const url = new URL(request.url);
    const ns = url.searchParams.get('namespace');
    const grade = url.searchParams.get('grade');
    const severity = url.searchParams.get('severity') as Severity | null;
    const q = url.searchParams.get('q')?.toLowerCase();
    const sort = url.searchParams.get('sort') ?? 'score';
    const order = (url.searchParams.get('order') ?? 'asc') as 'asc' | 'desc';
    const page = Math.max(1, Number(url.searchParams.get('page') ?? 1));
    const pageSize = Math.min(500, Math.max(1, Number(url.searchParams.get('pageSize') ?? 50)));
    let items = images.map(summaryOf);
    if (ns) items = items.filter((i) => i.namespaces.includes(ns));
    if (grade) {
      const grades = grade.split(',') as Grade[];
      items = items.filter((i) => grades.includes(i.grade));
    }
    if (severity) items = items.filter((i) => (Object.entries(i.counts) as [Severity, number][]).some(([s, n]) => n > 0 && severityRank(s) >= severityRank(severity)));
    if (q) items = items.filter((i) => i.ref.toLowerCase().includes(q) || (i.digest ?? '').includes(q));
    const current = url.searchParams.get('current');
    if (current !== null) items = items.filter((i) => (i.current !== false) === (current === 'true'));
    const stig = url.searchParams.get('stig');
    if (stig === 'evaluated') items = items.filter((i) => i.stig);
    else if (stig === 'na') items = items.filter((i) => !i.stig);
    else if (stig === 'cat1') items = items.filter((i) => (i.stig?.cat1Open ?? 0) > 0);
    items = sortImages(items, sort, order);
    return HttpResponse.json({ items: items.slice((page - 1) * pageSize, page * pageSize), total: items.length, page, pageSize });
  }),

  http.get(`${API}/images/:id`, ({ params, request }) => {
    const image = images.find((i) => i.id === params.id);
    return image ? HttpResponse.json({ ...imageWithFindingsPage(image, new URL(request.url).searchParams), stig: imageStigBrief(image.id) }) : HttpResponse.json({ detail: 'image not found' }, { status: 404 });
  }),
  http.get(`${API}/images/:id/stig`, ({ params, request }) => {
    if (!images.some((i) => i.id === params.id)) return HttpResponse.json({ detail: 'image not found' }, { status: 404 });
    return HttpResponse.json(imageStigResponse(String(params.id), new URL(request.url).searchParams));
  }),
  http.get(`${API}/stig/benchmarks`, () => HttpResponse.json(stigBenchmarkCatalogue())),
  http.get(`${API}/stig/benchmarks/:id/rules`, ({ params, request }) => {
    const rules = stigBenchmarkRules(String(params.id));
    if (!rules) return HttpResponse.json({ detail: 'benchmark not evaluated on any image' }, { status: 404 });
    const url = new URL(request.url);
    const page = Math.max(1, Number(url.searchParams.get('page') ?? 1) || 1);
    const pageSize = Math.min(500, Math.max(1, Number(url.searchParams.get('pageSize') ?? 100) || 100));
    const benchmark = stigBenchmarkRollup().find((b) => b.id === params.id) ?? null;
    return HttpResponse.json({ benchmark, items: rules.slice((page - 1) * pageSize, page * pageSize), total: rules.length, page, pageSize });
  }),

  http.get(`${API}/vulnerabilities`, ({ request }) => {
    const url = new URL(request.url);
    const severity = url.searchParams.get('severity');
    const q = url.searchParams.get('q')?.toLowerCase();
    const fixable = url.searchParams.get('fixable');
    const page = Math.max(1, Number(url.searchParams.get('page') ?? 1));
    const pageSize = Math.min(500, Math.max(1, Number(url.searchParams.get('pageSize') ?? 50)));
    let items: VulnSummary[] = [...vulnIndex().values()].map(({ finding, images: imgs }) => ({
      vulnId: finding.vulnId,
      severity: finding.severity,
      scanners: finding.scanners,
      agreement: finding.agreement,
      imagesAffected: imgs.length,
      workloadsAffected: imgs.reduce((a, i) => a + i.workloads, 0),
      fixAvailable: finding.fixable,
      cvss: finding.cvss,
      title: finding.title,
      url: finding.url,
      controls: finding.controls,
    }));
    if (severity) items = items.filter((v) => severity.split(',').includes(v.severity));
    if (fixable === 'true') items = items.filter((v) => v.fixAvailable);
    if (q) items = items.filter((v) => v.vulnId.toLowerCase().includes(q) || (v.title ?? '').toLowerCase().includes(q));
    items.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.imagesAffected - a.imagesAffected || (b.cvss ?? 0) - (a.cvss ?? 0));
    return HttpResponse.json({ items: items.slice((page - 1) * pageSize, page * pageSize), total: items.length, page, pageSize });
  }),

  http.get(`${API}/vulnerabilities/:vulnId`, ({ params }) => {
    const entry = vulnIndex().get(String(params.vulnId));
    if (!entry) return HttpResponse.json({ detail: 'vulnerability not found' }, { status: 404 });
    const { finding } = entry;
    return HttpResponse.json({
      vulnId: finding.vulnId,
      severity: finding.severity,
      scanners: finding.scanners,
      agreement: finding.agreement,
      imagesAffected: entry.images.length,
      workloadsAffected: entry.images.reduce((a, i) => a + i.workloads, 0),
      fixAvailable: finding.fixable,
      cvss: finding.cvss,
      title: finding.title,
      url: finding.url,
      controls: finding.controls,
      description: `${finding.title}. Reported by ${finding.scanners.join(', ')}.`,
      images: entry.images.map((i) => {
        const f = i.findings.find((x) => x.vulnId === finding.vulnId) ?? finding;
        return { imageId: i.id, ref: i.ref, grade: i.grade, score: i.score, package: f.package, installedVersion: f.installedVersion, fixedVersion: f.fixedVersion, perScanner: f.perScanner, namespaces: i.namespaces, workloads: i.workloads };
      }),
    });
  }),

  http.get(`${API}/workloads`, ({ request }) => {
    const url = new URL(request.url);
    const ns = url.searchParams.get('namespace');
    const kind = url.searchParams.get('kind');
    return HttpResponse.json(workloads.filter((w) => (!ns || w.namespace === ns) && (!kind || w.kind === kind)));
  }),
  http.get(`${API}/namespaces`, () => HttpResponse.json(namespaces)),
  http.get(`${API}/checks`, () => HttpResponse.json(checks)),
  http.get(`${API}/checks/:id`, ({ params }) => {
    const detail = checkDetailFor(String(params.id));
    return detail ? HttpResponse.json(detail) : HttpResponse.json({ detail: 'check not found' }, { status: 404 });
  }),

  http.get(`${API}/scans`, () => HttpResponse.json([...scans].map(advanceScan).reverse())),
  http.post(`${API}/scans`, async ({ request }) => {
    const body = (await request.json().catch(() => ({}))) as { imageIds?: string[] };
    const active = scans.find((s) => { advanceScan(s); return s.status === 'queued' || s.status === 'running'; });
    if (active && !body?.imageIds?.length) return HttpResponse.json({ detail: `scan ${active.id} is already running` }, { status: 409 });
    const id = Number(scans[scans.length - 1].id) + 1;
    const scan: Scan = { id, trigger: 'manual', status: 'queued', startedAt: null, finishedAt: null, imagesTotal: body?.imageIds?.length || images.length, imagesDone: 0, imagesFailed: 0, score: null, grade: null, requestedBy: me.username };
    scans.push(scan);
    scanStarted.set(String(id), Date.now());
    return HttpResponse.json(scan, { status: 202 });
  }),
  http.get(`${API}/scans/:id`, ({ params }) => {
    const scan = scans.find((s) => String(s.id) === params.id);
    if (!scan) return HttpResponse.json({ detail: 'scan not found' }, { status: 404 });
    advanceScan(scan);
    const detail = scanDetail(scan);
    if (scan.status === 'running' || scan.status === 'queued') {
      detail.log = [...detail.log.slice(0, 3), `progress: ${scan.imagesDone}/${scan.imagesTotal} images`];
    }
    return HttpResponse.json(detail);
  }),
  http.delete(`${API}/scans/:id`, ({ params }) => {
    const scan = scans.find((s) => String(s.id) === params.id);
    if (!scan) return HttpResponse.json({ detail: 'scan not found' }, { status: 404 });
    cancelled.add(String(scan.id));
    advanceScan(scan);
    return HttpResponse.json(scan);
  }),

  http.get(`${API}/scanners`, () =>
    HttpResponse.json(
      [...scannerHealth, scapScannerHealth].map((s) => ({ ...s, enabled: Boolean(settings.scanners[s.name as keyof Settings['scanners']]), lastRunAt: scans[scans.length - 1].finishedAt })),
    ),
  ),

  http.get(`${API}/settings`, () => HttpResponse.json(settings)),
  http.put(`${API}/settings`, async ({ request }) => {
    const body = (await request.json()) as Settings;
    if (!Number.isFinite(body.scanIntervalHours) || body.scanIntervalHours < 1) {
      return HttpResponse.json({ detail: 'scanIntervalHours must be >= 1' }, { status: 422 });
    }
    settings = { ...body, adminGroups: settings.adminGroups };
    return HttpResponse.json(settings);
  }),

  http.get(`${API}/reports/types`, () => HttpResponse.json(reportTypes)),
  http.get(`${API}/reports`, () => HttpResponse.json(reports.map(advanceReport))),
  http.post(`${API}/reports`, async ({ request }) => {
    const body = (await request.json()) as ReportCreate;
    const type = reportTypes.find((t) => t.type === body.type);
    if (!type || !type.formats.includes(body.format)) return HttpResponse.json({ detail: 'unsupported report type/format' }, { status: 422 });
    const id = `rpt-${String(reports.length + 1).padStart(4, '0')}-${Date.now() % 10000}`;
    const report: Report = { id, type: body.type, format: body.format, scope: body.scope ?? { kind: 'cluster' }, scanId: body.scanId ?? scans.filter((s) => s.status === 'done').at(-1)?.id ?? null, status: 'queued', createdAt: new Date().toISOString(), createdBy: me.username, sizeBytes: null, filename: null };
    reports.unshift(report);
    reportStarted.set(id, Date.now());
    return HttpResponse.json(report, { status: 202 });
  }),
  http.get(`${API}/reports/:id/download`, ({ params }) => {
    const report = reports.find((r) => String(r.id) === params.id);
    if (!report || report.status !== 'done') return HttpResponse.json({ detail: 'report not ready' }, { status: 404 });
    return new HttpResponse(`Mock ${report.type} report (${report.format}) for scan ${report.scanId}\n`, {
      headers: { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${report.filename}"` },
    });
  }),
  http.get(`${API}/reports/:id`, ({ params }) => {
    const report = reports.find((r) => String(r.id) === params.id);
    return report ? HttpResponse.json(advanceReport(report)) : HttpResponse.json({ detail: 'report not found' }, { status: 404 });
  }),
  http.delete(`${API}/reports/:id`, ({ params }) => {
    const index = reports.findIndex((r) => String(r.id) === params.id);
    if (index < 0) return HttpResponse.json({ detail: 'report not found' }, { status: 404 });
    reports.splice(index, 1);
    return new HttpResponse(null, { status: 204 });
  }),

  http.get(`${API}/compliance/controls`, () => {
    settleAssertionRun();
    return HttpResponse.json(controlCoverage());
  }),
  http.get(`${API}/compliance/catalog`, ({ request }) => {
    const family = new URL(request.url).searchParams.get('family');
    return HttpResponse.json(controlCoverage().filter((c) => !family || c.family === family.toUpperCase()).map(({ control, title, family: f, baseline }) => ({ control, title, family: f, baseline })));
  }),
  http.get(`${API}/compliance/families`, () => {
    settleAssertionRun();
    const all = controlCoverage();
    const baseline = 'moderate' as const;
    const items = rollupFamilies(all.filter((c) => c.inBaseline ?? inBaseline(c.baseline, baseline)));
    return HttpResponse.json({ baseline, items, totals: complianceTotals(all, baseline) });
  }),
  http.get(`${API}/compliance/assertions`, () => {
    settleAssertionRun();
    return HttpResponse.json(assertions());
  }),
  http.post(`${API}/compliance/assertions/run`, () => {
    if (assertionRunStarted !== null) return HttpResponse.json({ detail: 'an assertion run is already in progress' }, { status: 409 });
    assertionRunStarted = Date.now();
    return HttpResponse.json({ id: 1, status: 'queued', trigger: 'manual', createdAt: new Date(assertionRunStarted).toISOString(), startedAt: null }, { status: 202 });
  }),
  http.get(`${API}/compliance/assertions/:id`, ({ params }) => {
    settleAssertionRun();
    const a = assertions().find((x) => x.id === params.id);
    if (!a) return HttpResponse.json({ detail: 'assertion not found' }, { status: 404 });
    const history = [0, 1, 2, 3, 4].map((n) => ({ status: a.status, checkedAt: new Date(Date.parse(a.checkedAt ?? '') - n * 6 * 3_600_000).toISOString() }));
    return HttpResponse.json({ ...a, history });
  }),

  http.get(`${API}/supply-chain`, () => HttpResponse.json(supplyChainSummary())),
  http.get(`${API}/helm-releases`, () => HttpResponse.json(helmReleases)),
  http.get(`${API}/images/:id/sbom`, ({ params }) => {
    const image = images.find((i) => i.id === params.id);
    if (!image?.provenance?.sbom?.hasSBOM) return HttpResponse.json({ detail: 'no SBOM attestation' }, { status: 404 });
    return HttpResponse.json(
      { spdxVersion: 'SPDX-2.3', name: image.ref, packages: image.findings.slice(0, 5).map((f) => ({ name: f.package, versionInfo: f.installedVersion })) },
      { headers: { 'Content-Disposition': `attachment; filename="${image.repository.split('/').pop()}.sbom.json"` } },
    );
  }),
  http.get(`${API}/compliance/stig`, () => HttpResponse.json({ items: stigRules(), product: { benchmarks: stigBenchmarkRollup(), ...stigRollup() } })),

  http.get(`${API}/export`, ({ request }) => {
    const format = new URL(request.url).searchParams.get('format') ?? 'json';
    if (format === 'csv') {
      const rows = ['image,digest,grade,score,critical,high,medium,low', ...images.map((i) => [i.ref, i.digest, i.grade, i.score ?? '', i.counts.critical, i.counts.high, i.counts.medium, i.counts.low].join(','))];
      return new HttpResponse(rows.join('\n'), { headers: { 'Content-Type': 'text/csv' } });
    }
    return HttpResponse.json({ summary: buildSummary(), images: images.map(summaryOf), scanners: SCANNERS });
  }),
];
