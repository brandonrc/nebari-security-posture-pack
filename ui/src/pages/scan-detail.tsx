import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Square, TriangleAlert } from 'lucide-react';
import { useParams } from 'react-router';
import { api } from '@/api/client';
import { useScan } from '@/api/queries';
import { SCANNERS } from '@/api/types';
import { CardsSkeleton, ErrorAlert, Meta, PageHeader, errorMessage } from '@/components/page';
import { GradeBadge, SCANNER_LABEL, StatusBadge } from '@/components/posture';
import { ProgressBar } from '@/components/scan-control';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { toast } from '@/components/ui/toast';
import { durationBetween, formatDateTime, formatDuration } from '@/lib/format';
import { scanImageSummary } from '@/lib/scan-counts';
import { cn } from '@/lib/utils';

export function ScanDetailPage() {
  const { id = '' } = useParams();
  const { data: scan, error, isLoading, refetch } = useScan(id);
  const queryClient = useQueryClient();
  const cancel = useMutation({
    mutationFn: () => api.cancelScan(id),
    onSuccess: () => {
      toast.add({ title: `Cancelling scan #${id}`, type: 'info' });
      void queryClient.invalidateQueries({ queryKey: ['scan', id] });
    },
    onError: (e) => toast.add({ title: 'Cancel failed', description: errorMessage(e), type: 'error' }),
  });
  const running = scan?.status === 'running' || scan?.status === 'queued';

  return (
    <>
      <PageHeader
        title={`Scan #${id}`}
        crumbs={[{ label: 'Scans', to: '/scans' }, { label: `#${id}` }]}
        actions={
          running ? (
            <Button variant="destructive" onClick={() => cancel.mutate()} loading={cancel.isPending}>
              <Square />
              Cancel scan
            </Button>
          ) : null
        }
      />
      {error ? <ErrorAlert error={error} onRetry={() => void refetch()} /> : null}
      {isLoading ? <CardsSkeleton count={3} /> : null}
      {scan ? (
        <>
          <Card>
            <CardContent className="flex flex-col gap-4">
              <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
                <Meta label="Status">
                  <StatusBadge status={scan.status} />
                </Meta>
                <Meta label="Trigger">
                  {scan.trigger}
                  {scan.requestedBy ? <span className="text-muted-foreground"> · {scan.requestedBy}</span> : null}
                </Meta>
                <Meta label="Started">{formatDateTime(scan.startedAt)}</Meta>
                <Meta label="Duration">{formatDuration(durationBetween(scan.startedAt, scan.finishedAt))}</Meta>
                <Meta label="Images">
                  {scanImageSummary(scan)}
                  {scan.imagesFailed ? <span className="text-destructive-foreground"> · {scan.imagesFailed} failed</span> : null}
                </Meta>
                <Meta label="Score">{scan.grade ? <GradeBadge grade={scan.grade} score={scan.score} /> : '—'}</Meta>
              </div>
              {running ? <ProgressBar value={scan.imagesDone} max={scan.imagesTotal || 1} label="Scan progress" /> : null}
            </CardContent>
          </Card>
          {scan.warnings?.length ? (
            <Alert variant="warning">
              <TriangleAlert />
              <AlertTitle>Warnings</AlertTitle>
              <AlertDescription>
                <ul className="list-disc pl-4">
                  {scan.warnings.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          ) : null}
          <div className="grid gap-4 md:grid-cols-3">
            {SCANNERS.map((s) => {
              const r = scan.perScanner[s];
              const total = (r?.ok ?? 0) + (r?.error ?? 0);
              return (
                <Card key={s} size="sm">
                  <CardHeader>
                    <CardTitle>{SCANNER_LABEL[s]}</CardTitle>
                    <CardDescription>{r ? `${total} images attempted` : 'no runs recorded'}</CardDescription>
                  </CardHeader>
                  <CardContent className="flex items-baseline gap-4">
                    <span className="flex flex-col">
                      <span className="font-semibold text-2xl text-success-foreground tabular-nums">{r?.ok ?? 0}</span>
                      <span className="text-muted-foreground text-xs">ok</span>
                    </span>
                    <span className="flex flex-col">
                      <span className={cn('font-semibold text-2xl tabular-nums', r?.error ? 'text-destructive-foreground' : 'text-muted-foreground')}>{r?.error ?? 0}</span>
                      <span className="text-muted-foreground text-xs">error / timeout / unsupported</span>
                    </span>
                  </CardContent>
                </Card>
              );
            })}
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Log tail</CardTitle>
              <CardDescription>Most recent worker log lines for this scan</CardDescription>
            </CardHeader>
            <CardContent>
              {scan.log.length ? (
                <pre className="max-h-[420px] overflow-auto rounded-md bg-muted p-3 font-mono text-muted-foreground-strong text-xs leading-5">
                  {scan.log.map((line, i) => (
                    <div key={i} className={cn(/ERROR|FAILED|TIMEOUT/i.test(line) && 'text-destructive-foreground')}>
                      {line}
                    </div>
                  ))}
                </pre>
              ) : (
                <p className="text-muted-foreground text-sm">No log lines.</p>
              )}
            </CardContent>
          </Card>
        </>
      ) : null}
    </>
  );
}
