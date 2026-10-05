import { Link } from 'react-router';
import { useScans, useSummary } from '@/api/queries';
import type { Scan } from '@/api/types';
import { errorMessage, PageHeader } from '@/components/page';
import { GradeBadge, StatusBadge } from '@/components/posture';
import { ScanControl } from '@/components/scan-control';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { DataTable, type DataTableColumnDef } from '@/components/ui/data-table';
import { asRows, durationBetween, formatDateTime, formatDuration, formatRelative } from '@/lib/format';
import { scanImageSummary } from '@/lib/scan-counts';

type Row = Scan & Record<string, unknown>;

const columns: DataTableColumnDef<Row>[] = [
  {
    id: 'id',
    accessorFn: (s) => Number(s.id),
    header: 'Scan',
    cell: ({ row }) => (
      <Link to={`/scans/${encodeURIComponent(String(row.original.id))}`} className="font-medium tabular-nums underline-offset-4 hover:underline">
        #{row.original.id}
      </Link>
    ),
  },
  { id: 'status', accessorFn: (s) => s.status, header: 'Status', sortFn: 'text', cell: ({ row }) => <StatusBadge status={row.original.status} /> },
  {
    id: 'trigger',
    accessorFn: (s) => s.trigger,
    header: 'Trigger',
    sortFn: 'text',
    cell: ({ row }) => (
      <span className="flex flex-col">
        <Badge variant="outline">{row.original.trigger}</Badge>
        {row.original.requestedBy ? <span className="mt-0.5 text-muted-foreground text-xs">{row.original.requestedBy}</span> : null}
      </span>
    ),
  },
  {
    id: 'startedAt',
    accessorFn: (s) => s.startedAt ?? '',
    header: 'Started',
    sortFn: 'text',
    cell: ({ row }) => (
      <span className="flex flex-col text-xs">
        <span>{formatDateTime(row.original.startedAt)}</span>
        <span className="text-muted-foreground">{formatRelative(row.original.startedAt)}</span>
      </span>
    ),
  },
  {
    id: 'duration',
    accessorFn: (s) => durationBetween(s.startedAt, s.finishedAt) ?? -1,
    header: 'Duration',
    cell: ({ row }) => <span className="tabular-nums">{formatDuration(durationBetween(row.original.startedAt, row.original.finishedAt))}</span>,
  },
  {
    id: 'images',
    accessorFn: (s) => s.imagesRescanned ?? s.imagesDone,
    header: 'Images',
    cell: ({ row }) => (
      <span className="tabular-nums">
        {scanImageSummary(row.original)}
        {row.original.imagesFailed ? <span className="ml-1 text-destructive-foreground text-xs">({row.original.imagesFailed} failed)</span> : null}
      </span>
    ),
  },
  { id: 'score', accessorFn: (s) => s.score ?? -1, header: 'Score', cell: ({ row }) => (row.original.grade ? <GradeBadge grade={row.original.grade} score={row.original.score} /> : <span className="text-muted-foreground">—</span>) },
];

export function ScansPage() {
  const { data, error, isLoading, refetch } = useScans();
  const summary = useSummary();
  return (
    <>
      <PageHeader title="Scans" description="Scheduled, manual and event scan history. Images: rescanned now · still fresh (skipped) · unique images in the inventory; event scans show their target count." actions={<div className="w-64"><ScanControl lastScan={summary.data?.lastScan} compact /></div>} />
      <Card>
        <CardContent>
          <DataTable<Row>
            ariaLabel="Scan history"
            columns={columns}
            data={asRows(data)}
            getRowId={(s) => String(s.id)}
            selectable={false}
            showColumnVisibility={false}
            initialPageSize={20}
            pageSizeOptions={[20, 50, 100]}
            loading={isLoading}
            error={error ? errorMessage(error) : undefined}
            onRetry={() => void refetch()}
            emptyTitle="No scans yet"
            emptyDescription="Start the first scan with “Scan now”, or wait for the scheduler."
          />
        </CardContent>
      </Card>
    </>
  );
}
