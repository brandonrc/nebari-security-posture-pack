import { Link } from 'react-router';
import { useNamespaces } from '@/api/queries';
import type { Namespace } from '@/api/types';
import { errorMessage, PageHeader } from '@/components/page';
import { GradeBadge, PassFailBar, SeverityChips } from '@/components/posture';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { DataTable, type DataTableColumnDef } from '@/components/ui/data-table';
import { asRows } from '@/lib/format';

type Row = Namespace & Record<string, unknown>;

const columns: DataTableColumnDef<Row>[] = [
  {
    id: 'name',
    accessorFn: (n) => n.name,
    header: 'Namespace',
    filterFn: 'includesString',
    sortFn: 'text',
    cell: ({ row }) => (
      <span className="flex items-center gap-2">
        <span className="font-medium">{row.original.name}</span>
        {row.original.managed ? <Badge variant="secondary">managed</Badge> : null}
      </span>
    ),
  },
  {
    id: 'pack',
    accessorFn: (n) => n.pack ?? '',
    header: 'Pack',
    sortFn: 'text',
    cell: ({ row }) => (row.original.pack ? <Badge variant="outline">{row.original.pack}</Badge> : <span className="text-muted-foreground">—</span>),
  },
  { id: 'score', accessorFn: (n) => n.score ?? -1, header: 'Grade', cell: ({ row }) => <GradeBadge grade={row.original.grade} score={row.original.score} /> },
  { id: 'critical', accessorFn: (n) => n.counts.critical * 1000 + n.counts.high, header: 'Findings', cell: ({ row }) => <SeverityChips counts={row.original.counts} /> },
  {
    id: 'posture',
    accessorFn: (n) => n.posture.failed,
    header: 'Posture pass / fail',
    cell: ({ row }) => <PassFailBar passed={row.original.posture.passed} failed={row.original.posture.failed} className="w-40" />,
  },
  {
    id: 'workloads',
    accessorFn: (n) => n.workloads,
    header: 'Workloads',
    cell: ({ row }) => (
      <Link to={`/workloads?namespace=${encodeURIComponent(row.original.name)}`} className="tabular-nums underline-offset-4 hover:underline">
        {row.original.workloads}
      </Link>
    ),
  },
  {
    id: 'images',
    accessorFn: (n) => n.images,
    header: 'Images',
    cell: ({ row }) => (
      <Button variant="ghost" size="xs" render={<Link to={`/images?namespace=${encodeURIComponent(row.original.name)}`} />}>
        {row.original.images} images →
      </Button>
    ),
  },
];

export function NamespacesPage() {
  const { data, error, isLoading, refetch } = useNamespaces();
  return (
    <>
      <PageHeader title="Namespaces" description="Container-weighted namespace scores. Select a namespace's images to drill into them." />
      <Card>
        <CardContent>
          <DataTable<Row>
            ariaLabel="Namespaces"
            columns={columns}
            data={asRows(data)}
            getRowId={(n) => n.name}
            filterColumnId="name"
            filterPlaceholder="Filter namespaces…"
            selectable={false}
            initialPageSize={25}
            pageSizeOptions={[25, 50, 100]}
            loading={isLoading}
            error={error ? errorMessage(error) : undefined}
            onRetry={() => void refetch()}
            emptyTitle="No namespaces"
            emptyDescription="Nothing has been inventoried yet."
          />
        </CardContent>
      </Card>
    </>
  );
}
