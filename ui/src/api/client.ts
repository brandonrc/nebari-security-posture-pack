import { getAuthStrategy } from '@/auth/strategy';
import { isProvenanceMode } from '@/capabilities';
import { getConfig } from '@/config';
import { adaptMe, loadDataset, queryImages } from './provenance-adapter';
import type { PcMe, PcProvenanceReport, PcReportEntry, PcScanResponse } from './provenance-report';
import type {
  Assertion,
  AssertionRun,
  CheckDetail,
  FamiliesRollup,
  FamilyRollup,
  HelmRelease,
  SupplyChainSummary,
  Check,
  ControlCoverage,
  ImageDetail,
  ImageFindingsQuery,
  ImageQuery,
  ImageSummary,
  Me,
  Namespace,
  Page,
  Report,
  ReportCreate,
  ReportType,
  Scan,
  ScanCreate,
  ScanDetail,
  Scanner,
  Settings,
  StigRule,
  Summary,
  VulnDetail,
  VulnList,
  VulnQuery,
  Workload,
} from './types';
import * as normalize from './normalize';

export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    super(detail || `Request failed (${status})`);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

type Params = Record<string, string | number | boolean | undefined | null>;

function buildQuery(params?: Params): string {
  if (!params) return '';
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : '';
}

export function apiUrl(path: string, params?: Params): string {
  return `${getConfig().apiBase}${path}${buildQuery(params)}`;
}

/**
 * The single fetch layer. Auth comes from the active strategy (`src/auth/strategy.ts`): gateway
 * cookies in posture mode, a keycloak-js bearer in provenance mode (refreshed and retried once on
 * a 401).
 */
async function send(url: string, method: string, body?: unknown, accept = 'application/json'): Promise<Response> {
  const strategy = getAuthStrategy();
  const exec = async (forceRefresh: boolean) => {
    let auth: Record<string, string>;
    try {
      auth = await strategy.headers(forceRefresh);
    } catch (error) {
      throw new ApiError(401, error instanceof Error ? error.message : 'Session expired');
    }
    return fetch(url, {
      method,
      credentials: 'same-origin',
      headers: {
        Accept: accept,
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...auth,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  };
  let response = await exec(false);
  if (response.status === 401 && strategy.retryOn401) response = await exec(true);
  if (!response.ok) throw new ApiError(response.status, await errorDetail(response));
  return response;
}

/** FastAPI `{detail}` bodies, or the Go dashboard's `http.Error` plain text. */
async function errorDetail(response: Response): Promise<string> {
  let detail = response.statusText;
  try {
    const text = await response.text();
    try {
      const data = JSON.parse(text) as { detail?: unknown };
      if (typeof data.detail === 'string') detail = data.detail;
      else if (data.detail) detail = JSON.stringify(data.detail);
    } catch {
      if ((response.headers.get('content-type') ?? '').startsWith('text/plain') && text.trim()) detail = text.trim().slice(0, 300);
    }
  } catch {
    /* unreadable body */
  }
  return detail;
}

async function parse<T>(response: Response): Promise<T> {
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

async function request<T>(method: string, path: string, options: { params?: Params; body?: unknown } = {}): Promise<T> {
  return parse<T>(await send(apiUrl(path, options.params), method, options.body));
}

// ── provenance-collector dashboard (`/api/reports`, `/api/me`, `/api/scan`, `/api/export`) ──

export function pcUrl(path: string, params?: Params): string {
  return `${getConfig().provenanceApiBase}${path}${buildQuery(params)}`;
}

async function pcRequest<T>(method: string, path: string, params?: Params): Promise<T> {
  return parse<T>(await send(pcUrl(path, params), method));
}

const fetchReport = (name: string) => pcRequest<PcProvenanceReport>('GET', `/reports/${encodeURIComponent(name)}`);
const dataset = () => loadDataset(fetchReport);

/** Saves an authenticated GET (the bearer can't ride on a plain `<a href>`) as a file. */
export async function downloadFile(url: string, fallbackName: string): Promise<string> {
  const response = await send(url, 'GET', undefined, '*/*');
  const blob = await response.blob();
  const cd = response.headers.get('content-disposition') ?? '';
  const name = /filename="?([^";]+)"?/i.exec(cd)?.[1] ?? fallbackName;
  const href = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = href;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 0);
  return name;
}

export const provenanceApi = {
  me: async () => adaptMe(await pcRequest<PcMe>('GET', '/me'), getAuthStrategy().user()),
  reports: async () => {
    const r = await pcRequest<PcReportEntry[] | null>('GET', '/reports');
    return Array.isArray(r) ? r : [];
  },
  report: fetchReport,
  dataset,
  /** POST /api/scan — the browser adds `Sec-Fetch-Site: same-origin`, which the dashboard requires. */
  startScan: () => pcRequest<PcScanResponse>('POST', '/scan'),
  reportUrl: (filename: string | null) => pcUrl(`/reports/${encodeURIComponent(filename ?? 'latest')}`),
  exportUrl: (format: 'csv' | 'markdown', filename: string | null) => pcUrl('/export', { format, filename: filename ?? undefined }),
};

/** Accept either a bare array or a `{items}` envelope for list endpoints. */
function asArray<T>(data: T[] | { items: T[] } | null | undefined): T[] {
  if (Array.isArray(data)) return data;
  if (data && Array.isArray((data as { items: T[] }).items)) return (data as { items: T[] }).items;
  return [];
}

type RawScanDetail = Omit<ScanDetail, 'log'> & { log?: string[] | string; logs?: string[]; logTail?: string[] };

export const api = {
  me: (): Promise<Me> => (isProvenanceMode() ? provenanceApi.me() : request<Me>('GET', '/me')),
  summary: async (): Promise<Summary> => normalize.summary(await request<unknown>('GET', '/summary')),

  images: async (query: ImageQuery): Promise<Page<ImageSummary>> =>
    isProvenanceMode() ? queryImages(await dataset(), query) : normalize.page(await request<unknown>('GET', '/images', { params: { ...query } }), normalize.imageSummary),
  image: async (id: string, query: ImageFindingsQuery = {}): Promise<ImageDetail> => {
    if (isProvenanceMode()) {
      const detail = (await dataset()).details.get(id);
      if (!detail) throw new ApiError(404, `Image ${id} is not in this report`);
      return detail;
    }
    return normalize.imageDetail(await request<unknown>('GET', `/images/${encodeURIComponent(id)}`, { params: { ...query } }));
  },

  vulnerabilities: async (query: VulnQuery): Promise<VulnList> =>
    normalize.vulnList(await request<unknown>('GET', '/vulnerabilities', { params: { ...query } })),
  vulnerability: async (vulnId: string): Promise<VulnDetail> =>
    normalize.vulnDetail(await request<unknown>('GET', `/vulnerabilities/${encodeURIComponent(vulnId)}`)),

  workloads: async (params: { namespace?: string; kind?: string } = {}) =>
    asArray(await request<Workload[] | { items: Workload[] }>('GET', '/workloads', { params })),
  namespaces: async () => isProvenanceMode() ? (await dataset()).namespaces : asArray(await request<Namespace[] | { items: Namespace[] }>('GET', '/namespaces')),

  checks: async () => asArray(await request<Check[] | { items: Check[] }>('GET', '/checks')),
  check: async (id: string): Promise<CheckDetail> => normalize.checkDetail(await request<unknown>('GET', `/checks/${encodeURIComponent(id)}`)),

  scans: async (page = 1) => asArray(await request<Scan[] | { items: Scan[] }>('GET', '/scans', { params: { page } })),
  scan: async (id: string | number): Promise<ScanDetail> => {
    const raw = normalize.obj(await request<unknown>('GET', `/scans/${encodeURIComponent(String(id))}`)) as RawScanDetail;
    const log = raw.log ?? raw.logs ?? raw.logTail ?? [];
    return { ...raw, perScanner: raw.perScanner ?? {}, log: typeof log === 'string' ? log.split('\n') : normalize.arr(log) };
  },
  startScan: (body: ScanCreate = {}) => request<Scan>('POST', '/scans', { body }),
  cancelScan: (id: string | number) => request<unknown>('DELETE', `/scans/${encodeURIComponent(String(id))}`),

  scanners: async () => asArray(await request<Scanner[] | { items: Scanner[] }>('GET', '/scanners')),

  settings: async (): Promise<Settings> => normalize.settings(await request<unknown>('GET', '/settings')),
  saveSettings: (settings: Settings) => request<Settings>('PUT', '/settings', { body: settings }),

  reportTypes: async () => asArray(await request<ReportType[] | { items: ReportType[] }>('GET', '/reports/types')),
  reports: async (params: { scanId?: string | number; type?: string } = {}) =>
    asArray(await request<Report[] | { items: Report[] }>('GET', '/reports', { params })),
  report: (id: string | number) => request<Report>('GET', `/reports/${encodeURIComponent(String(id))}`),
  createReport: (body: ReportCreate) => request<Report>('POST', '/reports', { body }),
  deleteReport: (id: string | number) => request<unknown>('DELETE', `/reports/${encodeURIComponent(String(id))}`),
  reportDownloadUrl: (id: string | number) => apiUrl(`/reports/${encodeURIComponent(String(id))}/download`),

  complianceControls: async () =>
    asArray(await request<ControlCoverage[] | { items: ControlCoverage[] }>('GET', '/compliance/controls')),
  complianceFamilies: async (): Promise<FamiliesRollup> => {
    const r = await request<FamilyRollup[] | FamiliesRollup | undefined>('GET', '/compliance/families');
    return Array.isArray(r) ? { items: r } : { ...r, items: asArray(r?.items ?? []) };
  },
  assertions: async () => asArray(await request<Assertion[] | { items: Assertion[] }>('GET', '/compliance/assertions')),
  runAssertions: () => request<AssertionRun | undefined>('POST', '/compliance/assertions/run'),

  supplyChain: async (): Promise<SupplyChainSummary> =>
    isProvenanceMode() ? (await dataset()).supplyChain : normalize.supplyChain(await request<unknown>('GET', '/supply-chain')),
  helmReleases: async () => isProvenanceMode() ? (await dataset()).helmReleases : asArray(await request<HelmRelease[] | { items: HelmRelease[] }>('GET', '/helm-releases')),

  complianceStig: async () => asArray(await request<StigRule[] | { items: StigRule[] }>('GET', '/compliance/stig')),

  exportUrl: (format: 'json' | 'csv') => apiUrl('/export', { format }),
};
