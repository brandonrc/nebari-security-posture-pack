import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { useSyncExternalStore } from 'react';
import { isProvenanceMode } from '@/capabilities';
import { provenanceApi } from './client';
import { clearReportCache, setDataset, useDataset } from './provenance-adapter';
import type { PcReportEntry } from './provenance-report';

export const pqk = {
  reports: ['provenance', 'reports'] as const,
  report: (filename: string | null) => ['provenance', 'report', filename ?? 'latest'] as const,
};

/** How the UI follows a manual scan: the dashboard has no job-status endpoint, so poll the list. */
export const SCAN_POLL = { intervalMs: 5_000, maxMs: 5 * 60_000 };

export type ScanJobStatus = 'running' | 'done' | 'timeout';

export interface ScanJob {
  jobName: string;
  namespace: string;
  startedAt: number;
  /** newest report's `generatedAt` when the scan was requested */
  baseline: string | null;
  status: ScanJobStatus;
  /** the report the job produced, once seen */
  filename?: string;
}

let job: ScanJob | null = null;
const listeners = new Set<() => void>();

export function getScanJob(): ScanJob | null {
  return job;
}

export function setScanJob(next: ScanJob | null): void {
  job = next;
  for (const l of listeners) l();
}

export function useScanJob(): ScanJob | null {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => job,
    () => job,
  );
}

export const useProvenanceReports = () => {
  const running = useScanJob()?.status === 'running';
  return useQuery({
    queryKey: pqk.reports,
    queryFn: provenanceApi.reports,
    enabled: isProvenanceMode(),
    refetchInterval: running ? SCAN_POLL.intervalMs : false,
  });
};

/** The active dataset (latest, or the report picked with "View"), adapted. */
export const useProvenanceReport = () => {
  const filename = useDataset();
  return useQuery({ queryKey: pqk.report(filename), queryFn: () => provenanceApi.dataset(), enabled: isProvenanceMode() });
};

/** Every query except the reports list depends on the dataset. */
export function invalidateDataset(client: QueryClient) {
  return client.invalidateQueries({ predicate: (q) => !(q.queryKey[0] === 'provenance' && q.queryKey[1] === 'reports') });
}

export function useSwitchDataset() {
  const client = useQueryClient();
  return (filename: string | null) => {
    setDataset(filename);
    void invalidateDataset(client);
  };
}

const newest = (list: PcReportEntry[] | undefined) => list?.[0]?.generatedAt ?? null;

export function useRunProvenanceScan() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      let list = client.getQueryData<PcReportEntry[]>(pqk.reports);
      if (!list) list = await client.fetchQuery({ queryKey: pqk.reports, queryFn: provenanceApi.reports }).catch(() => undefined);
      const baseline = newest(list);
      const res = await provenanceApi.startScan();
      return { ...res, baseline };
    },
    onSuccess: ({ jobName, namespace, baseline }) => {
      setScanJob({ jobName: jobName || 'manual scan', namespace: namespace || '', startedAt: Date.now(), baseline, status: 'running' });
    },
  });
}

/**
 * Called with each fresh `/api/reports` list while a job runs: a report newer than the baseline
 * completes it (switch to latest, refetch everything); past `SCAN_POLL.maxMs` it times out.
 */
export function advanceScanJob(list: PcReportEntry[] | undefined, now = Date.now()): ScanJob | null {
  if (!job || job.status !== 'running') return null;
  const top = list?.[0];
  if (top && (job.baseline === null || top.generatedAt > job.baseline)) {
    const done: ScanJob = { ...job, status: 'done', filename: top.filename };
    setScanJob(done);
    return done;
  }
  if (now - job.startedAt > SCAN_POLL.maxMs) {
    const timedOut: ScanJob = { ...job, status: 'timeout' };
    setScanJob(timedOut);
    return timedOut;
  }
  return null;
}

/** After a scan lands: drop cached reports, view latest, refetch. */
export function adoptNewReport(client: QueryClient) {
  clearReportCache();
  setDataset(null);
  void invalidateDataset(client);
}
