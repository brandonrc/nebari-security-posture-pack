import { getConfig } from '@/config';
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

async function request<T>(method: string, path: string, options: { params?: Params; body?: unknown } = {}): Promise<T> {
  const response = await fetch(apiUrl(path, options.params), {
    method,
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      ...(options.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const data = (await response.json()) as { detail?: unknown };
      if (typeof data.detail === 'string') detail = data.detail;
      else if (data.detail) detail = JSON.stringify(data.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(response.status, detail);
  }
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

/** Accept either a bare array or a `{items}` envelope for list endpoints. */
function asArray<T>(data: T[] | { items: T[] } | null | undefined): T[] {
  if (Array.isArray(data)) return data;
  if (data && Array.isArray((data as { items: T[] }).items)) return (data as { items: T[] }).items;
  return [];
}

type RawScanDetail = Omit<ScanDetail, 'log'> & { log?: string[] | string; logs?: string[]; logTail?: string[] };

export const api = {
  me: () => request<Me>('GET', '/me'),
  summary: async (): Promise<Summary> => normalize.summary(await request<unknown>('GET', '/summary')),

  images: async (query: ImageQuery): Promise<Page<ImageSummary>> =>
    normalize.page(await request<unknown>('GET', '/images', { params: { ...query } }), normalize.imageSummary),
  image: async (id: string, query: ImageFindingsQuery = {}): Promise<ImageDetail> =>
    normalize.imageDetail(await request<unknown>('GET', `/images/${encodeURIComponent(id)}`, { params: { ...query } })),

  vulnerabilities: async (query: VulnQuery): Promise<VulnList> =>
    normalize.vulnList(await request<unknown>('GET', '/vulnerabilities', { params: { ...query } })),
  vulnerability: async (vulnId: string): Promise<VulnDetail> =>
    normalize.vulnDetail(await request<unknown>('GET', `/vulnerabilities/${encodeURIComponent(vulnId)}`)),

  workloads: async (params: { namespace?: string; kind?: string } = {}) =>
    asArray(await request<Workload[] | { items: Workload[] }>('GET', '/workloads', { params })),
  namespaces: async () => asArray(await request<Namespace[] | { items: Namespace[] }>('GET', '/namespaces')),

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

  supplyChain: async (): Promise<SupplyChainSummary> => normalize.supplyChain(await request<unknown>('GET', '/supply-chain')),
  helmReleases: async () => asArray(await request<HelmRelease[] | { items: HelmRelease[] }>('GET', '/helm-releases')),

  complianceStig: async () => asArray(await request<StigRule[] | { items: StigRule[] }>('GET', '/compliance/stig')),

  exportUrl: (format: 'json' | 'csv') => apiUrl('/export', { format }),
};
