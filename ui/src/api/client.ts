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
  summary: () => request<Summary>('GET', '/summary'),

  images: (query: ImageQuery) => request<Page<ImageSummary>>('GET', '/images', { params: { ...query } }),
  image: (id: string) => request<ImageDetail>('GET', `/images/${encodeURIComponent(id)}`),

  vulnerabilities: (query: VulnQuery) => request<VulnList>('GET', '/vulnerabilities', { params: { ...query } }),
  vulnerability: (vulnId: string) => request<VulnDetail>('GET', `/vulnerabilities/${encodeURIComponent(vulnId)}`),

  workloads: async (params: { namespace?: string; kind?: string } = {}) =>
    asArray(await request<Workload[] | { items: Workload[] }>('GET', '/workloads', { params })),
  namespaces: async () => asArray(await request<Namespace[] | { items: Namespace[] }>('GET', '/namespaces')),

  checks: async () => asArray(await request<Check[] | { items: Check[] }>('GET', '/checks')),
  check: (id: string) => request<CheckDetail>('GET', `/checks/${encodeURIComponent(id)}`),

  scans: async (page = 1) => asArray(await request<Scan[] | { items: Scan[] }>('GET', '/scans', { params: { page } })),
  scan: async (id: string | number): Promise<ScanDetail> => {
    const raw = await request<RawScanDetail>('GET', `/scans/${encodeURIComponent(String(id))}`);
    const log = raw.log ?? raw.logs ?? raw.logTail ?? [];
    return { ...raw, perScanner: raw.perScanner ?? {}, log: typeof log === 'string' ? log.split('\n') : log };
  },
  startScan: (body: ScanCreate = {}) => request<Scan>('POST', '/scans', { body }),
  cancelScan: (id: string | number) => request<unknown>('DELETE', `/scans/${encodeURIComponent(String(id))}`),

  scanners: async () => asArray(await request<Scanner[] | { items: Scanner[] }>('GET', '/scanners')),

  settings: () => request<Settings>('GET', '/settings'),
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

  supplyChain: () => request<SupplyChainSummary>('GET', '/supply-chain'),
  helmReleases: async () => asArray(await request<HelmRelease[] | { items: HelmRelease[] }>('GET', '/helm-releases')),

  complianceStig: async () => asArray(await request<StigRule[] | { items: StigRule[] }>('GET', '/compliance/stig')),

  exportUrl: (format: 'json' | 'csv') => apiUrl('/export', { format }),
};
