import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Play, Square } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';
import { ApiError, api } from '@/api/client';
import { useScan } from '@/api/queries';
import type { LastScan } from '@/api/types';
import { errorMessage } from '@/components/page';
import { StatusBadge } from '@/components/posture';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/toast';
import { formatScore } from '@/lib/format';

export function ProgressBar({ value, max, label }: { value: number; max: number; label?: string }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div
      className="h-2 w-full overflow-hidden rounded-full bg-muted"
      role="progressbar"
      aria-label={label ?? 'Progress'}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-valuenow={value}
    >
      <div className="h-full rounded-full bg-primary motion-safe:transition-[width] motion-safe:duration-(--duration-slow)" style={{ width: `${pct}%` }} />
    </div>
  );
}

/**
 * "Scan now" with inline live progress: POST /scans, then poll
 * GET /scans/{id} every 3s until it settles, toast on completion.
 */
export function ScanControl({ lastScan, compact = false }: { lastScan?: LastScan | null; compact?: boolean }) {
  const queryClient = useQueryClient();
  const [scanId, setScanId] = useState<string | number | null>(null);
  const announced = useRef<string | null>(null);

  // attach to an in-flight scan reported by /summary
  const activeId = scanId ?? (lastScan && (lastScan.status === 'running' || lastScan.status === 'queued') ? lastScan.id : null);
  const scan = useScan(activeId);

  const start = useMutation({
    mutationFn: () => api.startScan({}),
    onSuccess: (row) => {
      setScanId(row.id);
      toast.add({ title: `Scan #${row.id} queued`, description: 'Inventory and three-scanner analysis started.', type: 'info' });
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 409) {
        toast.add({ title: 'A scan is already running', description: error.detail, type: 'warning' });
        void queryClient.invalidateQueries({ queryKey: ['summary'] });
      } else {
        toast.add({ title: 'Could not start scan', description: errorMessage(error), type: 'error' });
      }
    },
  });

  const cancel = useMutation({
    mutationFn: (id: string | number) => api.cancelScan(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['scan'] }),
    onError: (error) => toast.add({ title: 'Cancel failed', description: errorMessage(error), type: 'error' }),
  });

  const data = scan.data;
  const status = data?.status;
  const inFlight = status === 'queued' || status === 'running';

  useEffect(() => {
    if (!data || inFlight) return;
    const key = `${data.id}:${data.status}`;
    if (announced.current === key || scanId === null) return;
    announced.current = key;
    if (data.status === 'done') {
      toast.add({
        title: `Scan #${data.id} complete`,
        description: `Cluster score ${formatScore(data.score)} (${data.grade ?? '?'}) · ${data.imagesDone} images, ${data.imagesFailed} failed.`,
        type: 'success',
      });
    } else if (data.status === 'failed') {
      toast.add({ title: `Scan #${data.id} failed`, description: data.log.at(-1) ?? 'See scan log for details.', type: 'error' });
    } else if (data.status === 'cancelled') {
      toast.add({ title: `Scan #${data.id} cancelled`, type: 'warning' });
    }
    for (const key of ['summary', 'images', 'scans', 'vulnerabilities', 'workloads', 'namespaces', 'checks']) {
      void queryClient.invalidateQueries({ queryKey: [key] });
    }
  }, [data, inFlight, queryClient, scanId]);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <Button onClick={() => start.mutate()} loading={start.isPending} disabled={inFlight} loadingText="Starting…">
          <Play />
          Scan now
        </Button>
        {inFlight && data ? (
          <Button variant="outline" size="default" onClick={() => cancel.mutate(data.id)} loading={cancel.isPending}>
            <Square />
            Cancel
          </Button>
        ) : null}
      </div>
      {inFlight && data ? (
        <div className="flex flex-col gap-1.5" aria-live="polite">
          <div className="flex items-center justify-between gap-2 text-xs">
            <span className="flex items-center gap-2">
              <StatusBadge status={data.status} />
              <Link to={`/scans/${data.id}`} className="text-muted-foreground underline-offset-4 hover:underline">
                Scan #{data.id}
              </Link>
            </span>
            <span className="text-muted-foreground tabular-nums">
              {data.imagesDone}/{data.imagesTotal} images
            </span>
          </div>
          <ProgressBar value={data.imagesDone} max={data.imagesTotal || 1} label={`Scan #${data.id} progress`} />
          {!compact && data.warnings?.length ? (
            <ul className="text-warning-foreground text-xs">
              {data.warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
