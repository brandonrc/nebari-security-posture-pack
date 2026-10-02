import { Link } from 'react-router';
import { useNamespaces, useWorkloads } from '@/api/queries';
import type { Workload } from '@/api/types';
import { errorMessage, PageHeader } from '@/components/page';
import { GradeBadge, PassFailBar, SeverityChips } from '@/components/posture';
import { SimpleSelect } from '@/components/simple-select';
import { useUrlState } from '@/components/table-kit';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { DataTable, type DataTableColumnDef } from '@/components/ui/data-table';
import { asRows } from '@/lib/format';

type Row = Workload & Record<string, unknown>;

const columns: DataTableColumnDef<Row>[] = [
  {
    id: 'name',
    accessorFn: (w) => `${w.namespace}/${w.name}`,
    header: 'Workload',
    filterFn: 'includesString',
    sortFn: 'text',
    cell: ({ row }) => (
      <span className="flex flex-col">
        <span className="font-medium">{row.original.name}</span>
        <span className="text-muted-foreground text-xs">
          {row.original.namespace} · {row.original.kind}
        </span>
      </span>
    ),
  },
  { id: 'score', accessorFn: (w) => w.score ?? -1, header: 'Grade', cell: ({ row }) => <GradeBadge grade={row.original.grade} score={row.original.score} /> },
  {
    id: 'critical',
    accessorFn: (w) => w.counts.critical * 1000 + w.counts.high,
    header: 'Findings',
    cell: ({ row }) => <SeverityChips counts={row.original.counts} />,
  },
  {
    id: 'posture',
    accessorFn: (w) => w.posture.failed,
    header: 'Posture pass / fail',
    cell: ({ row }) => <PassFailBar passed={row.original.posture.passed} failed={row.original.posture.failed} className="w-40" />,
  },
  { id: 'containers', accessorFn: (w) => w.containers, header: 'Containers' },
  {
    id: 'images',
    accessorFn: (w) => w.images.length,
    header: 'Images',
    enableSorting: false,
    cell: ({ row }) => (
      <span className="flex max-w-[280px] flex-col gap-0.5">
        {row.original.images.map((i) => (
          <Link key={i.imageId} to={`/images/${encodeURIComponent(i.imageId)}`} className="truncate font-mono text-xs underline-offset-4 hover:underline" title={i.ref}>
            {i.ref.split('/').pop()}
          </Link>
        ))}
      </span>
    ),
  },
  {
    id: 'pack',
    accessorFn: (w) => w.pack ?? '',
    header: 'Pack',
    sortFn: 'text',
    cell: ({ row }) => (row.original.pack ? <Badge variant="outline">{row.original.pack}</Badge> : <span className="text-muted-foreground">—</span>),
  },
];

export function WorkloadsPage() {
  const [state, update] = useUrlState({ namespace: '' });
  const { data, error, isLoading, refetch } = useWorkloads(state.namespace || undefined);
  const namespaces = useNamespaces();
  return (
    <>
      <PageHeader title="Workloads" description="Deployments, StatefulSets, DaemonSets, Jobs and CronJobs — 70% image vulnerability, 30% configuration posture." />
      <Card>
        <CardContent>
          <DataTable<Row>
            key={state.namespace}
            ariaLabel="Workloads"
            columns={columns}
            data={asRows(data)}
            getRowId={(w) => `${w.namespace}/${w.kind}/${w.name}`}
            filterColumnId="name"
            filterPlaceholder="Filter workloads…"
            selectable={false}
            initialPageSize={25}
            pageSizeOptions={[25, 50, 100]}
            loading={isLoading}
            error={error ? errorMessage(error) : undefined}
            onRetry={() => void refetch()}
            emptyTitle="No workloads"
            emptyDescription="No workloads were inventoried in the last scan."
            toolbarActions={
              <SimpleSelect
                ariaLabel="Namespace"
                allLabel="All namespaces"
                className="w-48"
                value={state.namespace}
                onChange={(namespace) => update({ namespace })}
                options={(namespaces.data ?? []).map((n) => ({ value: n.name, label: n.name }))}
              />
            }
          />
        </CardContent>
      </Card>
    </>
  );
}
