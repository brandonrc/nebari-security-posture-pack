import { Link } from 'react-router';
import { useChecks } from '@/api/queries';
import type { Check } from '@/api/types';
import { errorMessage, PageHeader } from '@/components/page';
import { ControlChips, PassFailBar, SeverityBadge } from '@/components/posture';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { DataTable, type DataTableColumnDef } from '@/components/ui/data-table';
import { asRows } from '@/lib/format';
import { severityRank } from '@/lib/scoring';

type Row = Check & Record<string, unknown>;

const columns: DataTableColumnDef<Row>[] = [
  {
    id: 'title',
    accessorFn: (c) => `${c.title} ${c.id} ${c.category}`,
    header: 'Check',
    filterFn: 'includesString',
    sortFn: 'text',
    cell: ({ row }) => (
      <span className="flex flex-col">
        <Link to={`/checks/${encodeURIComponent(row.original.id)}`} className="font-medium underline-offset-4 hover:underline">
          {row.original.title}
        </Link>
        <span className="font-mono text-muted-foreground text-xs">{row.original.id}</span>
      </span>
    ),
  },
  { id: 'severity', accessorFn: (c) => severityRank(c.severity), header: 'Severity', cell: ({ row }) => <SeverityBadge severity={row.original.severity} /> },
  { id: 'category', accessorFn: (c) => c.category, header: 'Category', sortFn: 'text', cell: ({ row }) => <Badge variant="outline">{row.original.category}</Badge> },
  {
    id: 'failed',
    accessorFn: (c) => c.failed,
    header: 'Pass / fail',
    cell: ({ row }) => <PassFailBar passed={row.original.passed} failed={row.original.failed} className="w-48" />,
  },
  { id: 'controls', accessorFn: (c) => (c.controls ?? []).join(' '), header: 'NIST controls', enableSorting: false, cell: ({ row }) => <ControlChips controls={row.original.controls} /> },
  {
    id: 'stig',
    accessorFn: (c) => c.stig?.vulnId ?? '',
    header: 'STIG',
    sortFn: 'text',
    cell: ({ row }) => (row.original.stig ? <span className="font-mono text-xs">{row.original.stig.vulnId}</span> : <span className="text-muted-foreground">—</span>),
  },
];

export function ChecksPage() {
  const { data, error, isLoading, refetch } = useChecks();
  return (
    <>
      <PageHeader title="Posture checks" description="Kubernetes configuration checks evaluated per container on every scan (kube-system weighted × 0.5)." />
      <Card>
        <CardContent>
          <DataTable<Row>
            ariaLabel="Posture checks"
            columns={columns}
            data={asRows(data)}
            getRowId={(c) => c.id}
            filterColumnId="title"
            filterPlaceholder="Filter checks…"
            selectable={false}
            showPagination={false}
            initialPageSize={100}
            loading={isLoading}
            error={error ? errorMessage(error) : undefined}
            onRetry={() => void refetch()}
            emptyTitle="No checks"
            emptyDescription="The posture check catalogue is empty."
          />
        </CardContent>
      </Card>
    </>
  );
}
