import { Clock } from 'lucide-react';
import { useProvenanceReports } from '@/api/provenance-queries';
import { useMe } from '@/api/queries';
import { EmptyState, ErrorAlert, PageHeader } from '@/components/page';
import { StatusBadge } from '@/components/posture';
import { RunScanButton, ScanJobStatus, useCanRunScan } from '@/components/provenance';
import { SkeletonRows, StateRow } from '@/components/table-kit';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { formatDateTime, formatRelative } from '@/lib/format';

/**
 * Scans in provenance mode. The dashboard exposes `POST /api/scan` (create a one-shot Job from the
 * collector CronJob) but no job-status endpoint, so a run is followed by polling `/api/reports`
 * until a newer report lands. History = one row per report the collector wrote.
 */
export function ProvenanceScansPage() {
  const canRun = useCanRunScan();
  const me = useMe();
  const { data, error, isLoading, refetch } = useProvenanceReports();
  const rows = data ?? [];
  return (
    <>
      <PageHeader title="Scans" description="Collector runs (scheduled by the CronJob, or started here)." actions={<RunScanButton />}>
        <ScanJobStatus />
      </PageHeader>
      {me.data && !canRun ? (
        <p className="text-muted-foreground text-sm">Manual scans are limited to the dashboard’s admin groups; scheduled runs continue as configured.</p>
      ) : null}
      {error ? <ErrorAlert error={error} onRetry={() => void refetch()} /> : null}
      <Card>
        <CardHeader>
          <CardTitle>Run history</CardTitle>
          <CardDescription>Each completed run leaves a timestamped report.</CardDescription>
        </CardHeader>
        <CardContent>
          <Table aria-label="Scans">
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="px-3">Finished</TableHead>
                <TableHead className="px-3">Status</TableHead>
                <TableHead className="px-3">Cluster</TableHead>
                <TableHead className="px-3 text-right">Containers</TableHead>
                <TableHead className="px-3 text-right">Unique images</TableHead>
                <TableHead className="px-3 text-right">Helm releases</TableHead>
                <TableHead className="px-3">Report</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <SkeletonRows cols={7} />
              ) : !rows.length ? (
                <StateRow cols={7}>
                  <EmptyState icon={<Clock className="size-6" />} title="No runs yet">
                    The first report appears after the collector CronJob (or a manual scan) completes.
                  </EmptyState>
                </StateRow>
              ) : (
                rows.map((r) => (
                  <TableRow key={r.filename}>
                    <TableCell className="whitespace-nowrap px-3 py-2">
                      {formatDateTime(r.generatedAt)}
                      <span className="ml-2 text-muted-foreground text-xs">{formatRelative(r.generatedAt)}</span>
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <StatusBadge status="done" />
                    </TableCell>
                    <TableCell className="px-3 py-2">{r.clusterName ?? '—'}</TableCell>
                    <TableCell className="px-3 py-2 text-right tabular-nums">{r.summary?.totalImages ?? 0}</TableCell>
                    <TableCell className="px-3 py-2 text-right tabular-nums">{r.summary?.uniqueImages ?? 0}</TableCell>
                    <TableCell className="px-3 py-2 text-right tabular-nums">{r.summary?.totalHelmReleases ?? 0}</TableCell>
                    <TableCell className="px-3 py-2 font-mono text-xs">{r.filename}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </>
  );
}
