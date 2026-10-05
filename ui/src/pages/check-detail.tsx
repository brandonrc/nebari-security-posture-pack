import { Wrench } from 'lucide-react';
import { useParams } from 'react-router';
import { useCheck } from '@/api/queries';
import type { CheckResult } from '@/api/types';
import { CardsSkeleton, ErrorAlert, Meta, PageHeader, errorMessage } from '@/components/page';
import { ControlChips, PassFailBar, SeverityBadge, StatusBadge } from '@/components/posture';
import { useUrlState } from '@/components/table-kit';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumnDef } from '@/components/ui/data-table';
import { Switch } from '@/components/ui/switch';
import { asRows } from '@/lib/format';

type Row = CheckResult & Record<string, unknown>;

const columns: DataTableColumnDef<Row>[] = [
  {
    id: 'workload',
    accessorFn: (r) => `${r.namespace}/${r.name} ${r.container ?? ''}`,
    header: 'Workload',
    filterFn: 'includesString',
    sortFn: 'text',
    cell: ({ row }) => (
      <span className="flex flex-col">
        <span>
          <span className="text-muted-foreground">{row.original.namespace}/</span>
          <span className="font-medium">{row.original.name}</span>
        </span>
        <span className="text-muted-foreground text-xs">
          {row.original.kind}
          {row.original.systemNamespace ? ' · system namespace (× 0.5)' : ''}
        </span>
      </span>
    ),
  },
  { id: 'container', accessorFn: (r) => r.container ?? '', header: 'Container', sortFn: 'text', cell: ({ row }) => <span className="font-mono text-xs">{row.original.container ?? '—'}</span> },
  { id: 'status', accessorFn: (r) => r.status, header: 'Result', sortFn: 'text', cell: ({ row }) => <StatusBadge status={row.original.status} /> },
  { id: 'detail', accessorFn: (r) => r.detail ?? '', header: 'Detail', enableSorting: false, cell: ({ row }) => <span className="text-muted-foreground text-xs">{row.original.detail ?? '—'}</span> },
];

export function CheckDetailPage() {
  const { id = '' } = useParams();
  const { data: check, error, isLoading, refetch } = useCheck(id);
  const [state, update] = useUrlState({ all: '' });
  const results = check ? (state.all ? check.results : check.results.filter((r) => r.status !== 'pass')) : [];

  return (
    <>
      <PageHeader title={check?.title ?? id} crumbs={[{ label: 'Posture checks', to: '/checks' }, { label: check?.title ?? id }]} description={check?.description} />
      {error ? <ErrorAlert error={error} onRetry={() => void refetch()} /> : null}
      {isLoading ? <CardsSkeleton count={2} /> : null}
      {check ? (
        <>
          <Card>
            <CardContent className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
              <Meta label="Severity">
                <SeverityBadge severity={check.severity} />
              </Meta>
              <Meta label="Category">{check.category}</Meta>
              <Meta label="Results">
                <PassFailBar passed={check.passed} failed={check.failed} />
                {check.acceptedRisk ? (
                  <span className="mt-1 block text-xs text-muted-foreground" title="Failing results covered by an approved risk acceptance (controlsEngine.exceptions): listed, no score penalty, never a pass">
                    + {check.acceptedRisk} accepted risk
                  </span>
                ) : null}
              </Meta>
              <Meta label="NIST 800-53">
                <ControlChips controls={check.controls} max={4} />
              </Meta>
              <Meta label="STIG rule">
                {check.stig ? (
                  <span className="flex flex-col">
                    <span className="font-mono text-xs">
                      {check.stig.vulnId}
                      {check.stig.cat ? <Badge variant="outline" className="ml-1.5">CAT {check.stig.cat}</Badge> : null}
                    </span>
                    <span className="font-mono text-[11px] text-muted-foreground">{check.stig.ruleId}</span>
                  </span>
                ) : (
                  <span className="text-muted-foreground">not mapped</span>
                )}
              </Meta>
              <Meta label="Check id">
                <span className="font-mono text-xs">{check.id}</span>
              </Meta>
            </CardContent>
          </Card>
          <Alert>
            <Wrench />
            <AlertTitle>Remediation</AlertTitle>
            <AlertDescription className="whitespace-pre-wrap">{check.remediation}</AlertDescription>
          </Alert>
          <Card>
            <CardHeader>
              <CardTitle>{state.all ? 'All evaluated containers' : 'Offenders'}</CardTitle>
            </CardHeader>
            <CardContent>
              <DataTable<Row>
                key={state.all}
                ariaLabel="Check results"
                columns={columns}
                data={asRows(results)}
                filterColumnId="workload"
                filterPlaceholder="Filter workloads…"
                selectable={false}
                initialPageSize={25}
                pageSizeOptions={[25, 50, 100]}
                error={error ? errorMessage(error) : undefined}
                emptyTitle="No offenders"
                emptyDescription="Every evaluated container passes this check."
                toolbarActions={
                  <label className="ml-auto flex items-center gap-2 text-sm">
                    <Switch checked={Boolean(state.all)} onCheckedChange={(v) => update({ all: v ? '1' : '' })} aria-label="Show passing containers" />
                    Show passing
                  </label>
                }
              />
            </CardContent>
          </Card>
        </>
      ) : null}
    </>
  );
}
