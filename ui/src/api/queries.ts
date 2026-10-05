import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { getCapabilities } from '@/capabilities';
import { api } from './client';
import { scapInProgress } from '@/lib/scan-counts';
import type { ImageFindingsQuery, ImageQuery, ImageStigQuery, VulnQuery } from './types';

export const qk = {
  me: ['me'] as const,
  summary: ['summary'] as const,
  images: (q: ImageQuery) => ['images', q] as const,
  image: (id: string, q: ImageFindingsQuery = {}) => ['image', id, q] as const,
  vulns: (q: VulnQuery) => ['vulnerabilities', q] as const,
  vuln: (id: string) => ['vulnerability', id] as const,
  workloads: (ns?: string) => ['workloads', ns ?? ''] as const,
  namespaces: ['namespaces'] as const,
  checks: ['checks'] as const,
  check: (id: string) => ['check', id] as const,
  scans: ['scans'] as const,
  scan: (id: string | number) => ['scan', String(id)] as const,
  scanners: ['scanners'] as const,
  settings: ['settings'] as const,
  reportTypes: ['reportTypes'] as const,
  reports: ['reports'] as const,
  controls: ['compliance', 'controls'] as const,
  stig: ['compliance', 'stig'] as const,
  families: ['compliance', 'families'] as const,
  assertions: ['compliance', 'assertions'] as const,
  supplyChain: ['supplyChain'] as const,
  helmReleases: ['helmReleases'] as const,
  imageStig: (id: string, q: ImageStigQuery = {}) => ['imageStig', id, q] as const,
  stigBenchmarks: ['stig', 'benchmarks'] as const,
  stigBenchmarkRules: (id: string) => ['stig', 'benchmarks', id, 'rules'] as const,
};

export const useMe = () => useQuery({ queryKey: qk.me, queryFn: api.me, staleTime: 5 * 60_000 });
/** Posture-only: provenance mode has no `/summary` (pages that share it treat it as absent). */
export const useSummary = () =>
  useQuery({ queryKey: qk.summary, queryFn: api.summary, refetchInterval: 60_000, enabled: getCapabilities().mode === 'posture' });
export const useImages = (q: ImageQuery) =>
  useQuery({ queryKey: qk.images(q), queryFn: () => api.images(q), placeholderData: keepPreviousData });
/** Image detail; `q` pages/filters the findings server-side. Keeps the previous page while the next loads. */
export const useImage = (id: string, q: ImageFindingsQuery = {}) =>
  useQuery({
    queryKey: qk.image(id, q),
    queryFn: () => api.image(id, q),
    // keep the header/tabs while another findings page loads, but never show another image's data
    placeholderData: (prev, prevQuery) => (prevQuery?.queryKey[1] === id ? prev : undefined),
  });
export const useVulns = (q: VulnQuery) =>
  useQuery({ queryKey: qk.vulns(q), queryFn: () => api.vulnerabilities(q), placeholderData: keepPreviousData });
export const useVuln = (id: string) => useQuery({ queryKey: qk.vuln(id), queryFn: () => api.vulnerability(id) });
export const useWorkloads = (namespace?: string) =>
  useQuery({ queryKey: qk.workloads(namespace), queryFn: () => api.workloads({ namespace }) });
export const useNamespaces = () => useQuery({ queryKey: qk.namespaces, queryFn: api.namespaces });
export const useChecks = () => useQuery({ queryKey: qk.checks, queryFn: api.checks });
export const useCheck = (id: string) => useQuery({ queryKey: qk.check(id), queryFn: () => api.check(id) });
export const useScans = () => useQuery({ queryKey: qk.scans, queryFn: () => api.scans(1), refetchInterval: 15_000 });
export const useScanners = (enabled = true) => useQuery({ queryKey: qk.scanners, queryFn: api.scanners, enabled });
export const useSettings = () => useQuery({ queryKey: qk.settings, queryFn: api.settings });
export const useReportTypes = () => useQuery({ queryKey: qk.reportTypes, queryFn: api.reportTypes, staleTime: Infinity });
export const useControls = () => useQuery({ queryKey: qk.controls, queryFn: api.complianceControls });
export const useFamilies = () => useQuery({ queryKey: qk.families, queryFn: api.complianceFamilies });
export const useAssertions = () => useQuery({ queryKey: qk.assertions, queryFn: api.assertions });
export const useSupplyChain = () => useQuery({ queryKey: qk.supplyChain, queryFn: api.supplyChain });
export const useHelmReleases = () => useQuery({ queryKey: qk.helmReleases, queryFn: api.helmReleases });
export const useStig = () => useQuery({ queryKey: qk.stig, queryFn: api.complianceStig });

// §14 SCAP (posture mode only: the provenance dashboard has no SCAP data)
const posture = () => getCapabilities().mode === 'posture';
/** One image's benchmarks; `q` pages/filters the rules server-side. */
export const useImageStig = (id: string, q: ImageStigQuery = {}) =>
  useQuery({
    queryKey: qk.imageStig(id, q),
    queryFn: () => api.imageStig(id, q),
    enabled: posture() && Boolean(id),
    placeholderData: (prev, prevQuery) => (prevQuery?.queryKey[1] === id ? prev : undefined),
  });
export const useStigBenchmarks = (enabled = true) =>
  useQuery({ queryKey: qk.stigBenchmarks, queryFn: api.stigBenchmarks, enabled: enabled && posture() });
export const useStigBenchmarkRules = (id: string) =>
  useQuery({ queryKey: qk.stigBenchmarkRules(id), queryFn: () => api.stigBenchmarkRules(id), enabled: posture() && Boolean(id) });

/** Poll a scan every 3s while it's queued/running (DESIGN §7). */
export const useScan = (id: string | number | null | undefined) =>
  useQuery({
    queryKey: qk.scan(id ?? ''),
    queryFn: () => api.scan(id as string | number),
    enabled: id !== null && id !== undefined && id !== '',
    refetchInterval: (query) => {
      const data = query.state.data;
      const status = data?.status;
      if (status === 'queued' || status === 'running' || status === undefined) return 3000;
      return data && scapInProgress(data) ? 10_000 : false; // §14: STIG evaluation after the scan
    },
  });

export const useReports = () =>
  useQuery({
    queryKey: qk.reports,
    queryFn: () => api.reports(),
    refetchInterval: (query) =>
      query.state.data?.some((r) => r.status === 'queued' || r.status === 'running') ? 3000 : false,
  });
