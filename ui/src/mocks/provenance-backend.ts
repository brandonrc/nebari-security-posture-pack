/**
 * provenance-collector-pack's Go dashboard, mocked from its golden report
 * (`testdata/report.golden.json`, vendored in `fixtures/`). Mirrors `internal/dashboard`:
 * `/api/reports` (+ `/{filename|latest}`), `/api/me`, `POST /api/scan`, `/api/export`; reads and
 * export require `Authorization: Bearer <MOCK_BEARER>` (auth enabled), errors are plain text.
 * No `/api/v1/*` → capability detection lands in provenance mode.
 *
 * `?mockAuth=viewer` → signed in but not in an admin group (`canRunScan: false`);
 * `?mockAuth=401` → every token rejected; `?mockAuth=noauth` → dashboard with OIDC disabled.
 */
import { delay, http, HttpResponse } from 'msw';
import type { PcImageRecord, PcProvenanceReport, PcReportEntry, PcReportSummary } from '@/api/provenance-report';
import golden from './fixtures/report.golden.json';

export const MOCK_BEARER = 'mock-provenance-token';
export const MOCK_USER = { name: 'Ada Admin', preferred_username: 'ada', email: 'ada@example.com', sub: 'ada' };
const PC = '*/api';

export const goldenReport = golden as PcProvenanceReport;

export function summarize(images: PcImageRecord[], helm: PcProvenanceReport['helmReleases'] = []): PcReportSummary {
  return {
    totalImages: images.length,
    uniqueImages: new Set(images.map((i) => i.image)).size,
    signedImages: images.filter((i) => i.signature?.signed).length,
    verifiedImages: images.filter((i) => i.signature?.signed && i.signature.verified).length,
    imagesWithSBOM: images.filter((i) => i.sbom?.hasSBOM).length,
    imagesWithProvenance: images.filter((i) => i.provenance?.hasProvenance).length,
    imagesWithUpdates: images.filter((i) => i.update?.updateAvailable).length,
    totalHelmReleases: helm.length,
    helmReleasesWithUpdates: helm.filter((h) => h.update?.updateAvailable).length,
  };
}

export function reportFilename(iso: string): string {
  const d = new Date(iso);
  const p = (n: number) => String(n).padStart(2, '0');
  return `provenance-${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}-${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}.json`;
}

function at(base: PcProvenanceReport, iso: string, images = base.images, extra: Partial<PcProvenanceReport> = {}): PcProvenanceReport {
  const r: PcProvenanceReport = { ...structuredClone(base), ...extra, images: structuredClone(images) };
  r.metadata = { ...r.metadata, generatedAt: iso };
  r.summary = summarize(r.images, r.helmReleases);
  return r;
}

/** Seed history: the golden report plus two older runs (fewer images, nothing verified yet). */
function seed(): Map<string, PcProvenanceReport> {
  const older = goldenReport.images.filter((i) => i.namespace !== 'monitoring');
  const oldest = older
    .filter((i) => i.workload.kind !== 'Pod')
    .map((i) => (i.signature ? { ...i, signature: { ...i.signature, verified: false } } : i));
  const reports = [
    at(goldenReport, '2026-10-01T12:00:00Z', oldest, { warnings: [] }),
    at(goldenReport, '2026-10-02T12:00:00Z', older),
    at(goldenReport, goldenReport.metadata.generatedAt),
  ];
  return new Map(reports.map((r) => [reportFilename(r.metadata.generatedAt), r]));
}

let reports = seed();
let activeJob: { name: string; done: number } | null = null;
let jobSeq = 0;
/** How long a manual scan "runs" before its report lands. */
export const mockScan = { durationMs: 8_000 };

export function resetProvenanceMock(): void {
  reports = seed();
  activeJob = null;
  jobSeq = 0;
}

function mockAuth(): string | null {
  if (typeof window === 'undefined' || !window.location) return null;
  return new URLSearchParams(window.location.search).get('mockAuth');
}

const authEnabled = () => mockAuth() !== 'noauth';

function identify(request: Request): boolean {
  if (mockAuth() === '401') return false;
  return request.headers.get('authorization') === `Bearer ${MOCK_BEARER}`;
}

const text = (body: string, status: number) => new HttpResponse(`${body}\n`, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });

/** `requireAuth`: 401 when auth is enabled and the bearer doesn't identify anyone. */
const unauthorized = (request: Request) => (authEnabled() && !identify(request) ? text('unauthorized', 401) : null);

function settleJob() {
  if (activeJob && Date.now() >= activeJob.done) {
    const iso = new Date(activeJob.done).toISOString().replace(/\.\d{3}Z$/, 'Z');
    reports.set(reportFilename(iso), at(goldenReport, iso));
    activeJob = null;
  }
}

function sorted(): Array<[string, PcProvenanceReport]> {
  settleJob();
  return [...reports.entries()].sort((a, b) => b[1].metadata.generatedAt.localeCompare(a[1].metadata.generatedAt));
}

function find(filename: string): PcProvenanceReport | undefined {
  const all = sorted();
  return filename === 'latest' || filename === 'provenance-latest.json' ? all[0]?.[1] : reports.get(filename);
}

const csvEscape = (s: string) => (/[",\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s);

export function exportCsv(r: PcProvenanceReport): string {
  const head = 'Image,Namespace,Workload Kind,Workload Name,Digest,Signed,Verified,SLSA Provenance,SBOM,SBOM Format,Update Available,Current Tag,Latest In Major\n';
  return (
    head +
    r.images
      .map((i) =>
        [
          csvEscape(i.image),
          csvEscape(i.namespace),
          csvEscape(i.workload.kind),
          csvEscape(i.workload.name),
          csvEscape(i.digest ?? ''),
          String(Boolean(i.signature?.signed)),
          String(Boolean(i.signature?.verified)),
          String(Boolean(i.provenance?.hasProvenance)),
          String(Boolean(i.sbom?.hasSBOM)),
          csvEscape(i.sbom?.format ?? ''),
          String(Boolean(i.update?.updateAvailable)),
          csvEscape(i.update?.currentTag ?? ''),
          csvEscape(i.update?.latestInMajor ?? ''),
        ].join(','),
      )
      .map((l) => `${l}\n`)
      .join('')
  );
}

export function exportMarkdown(r: PcProvenanceReport): string {
  const s = r.summary;
  return [
    '# Provenance Report',
    '',
    `**Generated:** ${r.metadata.generatedAt}`,
    '',
    r.metadata.clusterName ? `**Cluster:** ${r.metadata.clusterName}\n` : '',
    '## Summary',
    '',
    '| Metric | Count |',
    '|---|---|',
    `| Unique Images | ${s.uniqueImages} |`,
    `| Signed | ${s.signedImages} |`,
    `| Helm Releases | ${s.totalHelmReleases} |`,
    '',
  ].join('\n');
}

const latency = () => delay(typeof window === 'undefined' ? 0 : 100 + Math.random() * 200);

export const provenanceHandlers = [
  // the posture API doesn't exist here: the Go mux answers unknown paths with 404
  http.all('*/api/v1/*', () => text('404 page not found', 404)),

  http.get(`${PC}/me`, async ({ request }) => {
    await latency();
    const ok = authEnabled() && identify(request);
    return HttpResponse.json({
      authEnabled: authEnabled(),
      ...(ok ? { email: MOCK_USER.email, groups: mockAuth() === 'viewer' ? ['developer'] : ['admin', 'developer'] } : {}),
      canRunScan: ok && mockAuth() !== 'viewer',
      features: { timelineDeltas: true },
    });
  }),

  http.get(`${PC}/reports`, async ({ request }) => {
    await latency();
    const denied = unauthorized(request);
    if (denied) return denied;
    const list: PcReportEntry[] = sorted().map(([filename, r]) => ({
      filename,
      generatedAt: r.metadata.generatedAt,
      summary: r.summary,
      ...(r.metadata.clusterName ? { clusterName: r.metadata.clusterName } : {}),
    }));
    return HttpResponse.json(list);
  }),

  http.get(`${PC}/reports/:filename`, async ({ request, params }) => {
    await latency();
    const denied = unauthorized(request);
    if (denied) return denied;
    const filename = String(params.filename);
    if (filename.includes('..')) return text('invalid filename', 400);
    const r = find(filename);
    return r ? HttpResponse.json(r) : text('report not found', 404);
  }),

  http.get(`${PC}/export`, async ({ request }) => {
    await latency();
    const denied = unauthorized(request);
    if (denied) return denied;
    const url = new URL(request.url);
    const format = url.searchParams.get('format') || 'csv';
    const r = find(url.searchParams.get('filename') || 'latest');
    if (!r) return text('report not found', 404);
    if (format === 'csv') {
      return new HttpResponse(exportCsv(r), { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=provenance-report.csv' } });
    }
    if (format === 'markdown' || format === 'md') {
      return new HttpResponse(exportMarkdown(r), {
        headers: { 'Content-Type': 'text/markdown', 'Content-Disposition': 'attachment; filename=provenance-report.md' },
      });
    }
    return text('unsupported format: use csv or markdown', 400);
  }),

  // Sec-Fetch-Site is set by the browser below the service worker, so the mock can't check it.
  http.post(`${PC}/scan`, async ({ request }) => {
    await latency();
    if (!authEnabled()) return text('scan endpoint is not configured (oidcIssuer/adminGroups unset)', 503);
    if (!identify(request) || mockAuth() === 'viewer') return text('forbidden: caller is not in an admin group', 403);
    settleJob();
    if (activeJob) return text('a scan job is already active for this collector', 409);
    jobSeq += 1;
    activeJob = { name: `manual-${String(jobSeq).padStart(5, 'x')}`, done: Date.now() + mockScan.durationMs };
    return HttpResponse.json({ jobName: activeJob.name, namespace: 'provenance' });
  }),
  http.all(`${PC}/scan`, () => new HttpResponse('method not allowed\n', { status: 405, headers: { Allow: 'POST' } })),
];
