import { useQueryClient } from '@tanstack/react-query';
import { History, Play } from 'lucide-react';
import { useEffect, useRef } from 'react';
import { ApiError } from '@/api/client';
import { useDataset } from '@/api/provenance-adapter';
import {
  adoptNewReport,
  advanceScanJob,
  useProvenanceReport,
  useProvenanceReports,
  useRunProvenanceScan,
  useScanJob,
  useSwitchDataset,
} from '@/api/provenance-queries';
import type { ProvenanceMe } from '@/api/provenance-adapter';
import { useMe } from '@/api/queries';
import { errorMessage } from '@/components/page';
import { StatusBadge } from '@/components/posture';
import { Alert, AlertAction, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/toast';
import { formatDateTime, formatRelative } from '@/lib/format';

const SCAN_ERRORS: Record<number, string> = {
  403: 'Only members of the dashboard’s admin groups can run a scan.',
  409: 'A scan job is already running for this collector.',
  503: 'Manual scans are not configured on the dashboard (OIDC issuer / admin groups or Kubernetes access missing).',
};

/** `/api/me`'s `canRunScan` gates the button; members of the admin groups only. */
export function useCanRunScan(): boolean {
  const { data } = useMe();
  return Boolean((data as ProvenanceMe | undefined)?.canRunScan);
}

/** POST /api/scan, then follow the job by polling `/api/reports` (see ProvenanceScanWatcher). */
export function RunScanButton() {
  const canRun = useCanRunScan();
  const job = useScanJob();
  const run = useRunProvenanceScan();
  if (!canRun) return null;
  const running = job?.status === 'running';
  return (
    <Button
      onClick={() =>
        run.mutate(undefined, {
          onSuccess: (r) => toast.add({ title: 'Scan started', description: r.jobName ? `Job ${r.namespace ? `${r.namespace}/` : ''}${r.jobName}` : undefined, type: 'info' }),
          onError: (error) =>
            toast.add({
              title: error instanceof ApiError && error.status === 409 ? 'A scan is already running' : 'Could not start scan',
              description: (error instanceof ApiError && SCAN_ERRORS[error.status]) || errorMessage(error),
              type: error instanceof ApiError && error.status === 409 ? 'warning' : 'error',
            }),
        })
      }
      loading={run.isPending}
      loadingText="Starting…"
      disabled={running}
    >
      <Play />
      {running ? 'Scan running…' : 'Run scan'}
    </Button>
  );
}

/** Inline status of the last manual scan job requested from this browser. */
export function ScanJobStatus() {
  const job = useScanJob();
  if (!job) return null;
  const status = job.status === 'done' ? 'done' : job.status === 'timeout' ? 'unknown' : 'running';
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm" aria-live="polite" aria-label="Scan job status">
      <StatusBadge status={status} />
      <span className="font-mono text-xs">
        {job.namespace ? `${job.namespace}/` : ''}
        {job.jobName}
      </span>
      <span className="text-muted-foreground text-xs">started {formatRelative(new Date(job.startedAt).toISOString())}</span>
      {job.status === 'done' && job.filename ? <span className="text-muted-foreground text-xs">→ {job.filename}</span> : null}
      {job.status === 'timeout' ? <span className="text-muted-foreground text-xs">no new report after 5 min — check the Job’s pod logs</span> : null}
    </div>
  );
}

/** Mounted once in the layout (provenance mode): polls while a job runs, adopts its report. */
export function ProvenanceScanWatcher() {
  const client = useQueryClient();
  const job = useScanJob();
  const reports = useProvenanceReports();
  const last = useRef<number>(0);
  useEffect(() => {
    if (job?.status !== 'running' || !reports.data || reports.dataUpdatedAt === last.current) return;
    last.current = reports.dataUpdatedAt;
    const next = advanceScanJob(reports.data);
    if (next?.status === 'done') {
      adoptNewReport(client);
      toast.add({ title: 'New report available', description: next.filename, type: 'success' });
    } else if (next?.status === 'timeout') {
      toast.add({ title: 'Scan still running', description: 'Stopped watching after 5 min — refresh later.', type: 'warning' });
    }
  }, [client, job, reports.data, reports.dataUpdatedAt]);
  return null;
}

/** Shown while a historical report (not `latest`) is the active dataset. */
export function DatasetBanner() {
  const dataset = useDataset();
  const report = useProvenanceReport();
  const switchTo = useSwitchDataset();
  if (dataset === null) return null;
  return (
    <Alert>
      <History />
      <AlertTitle>Viewing an earlier report</AlertTitle>
      <AlertDescription>
        {report.data?.meta.generatedAt ? `Generated ${formatDateTime(report.data.meta.generatedAt)} · ` : ''}
        <span className="font-mono text-xs">{dataset}</span>. Images, supply chain and Helm releases show this report.
      </AlertDescription>
      <AlertAction>
        <Button variant="outline" size="sm" onClick={() => switchTo(null)}>
          Back to latest
        </Button>
      </AlertAction>
    </Alert>
  );
}

