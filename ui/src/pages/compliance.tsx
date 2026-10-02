import { Clock } from 'lucide-react';
import { Link } from 'react-router';
import { useControls, useStig, useSummary } from '@/api/queries';
import type { ControlCoverage, Severity, StigOffender, StigRule } from '@/api/types';
import { CardsSkeleton, ErrorAlert, errorMessage, PageHeader } from '@/components/page';
import { StatusBadge } from '@/components/posture';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumnDef } from '@/components/ui/data-table';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { asRows } from '@/lib/format';
import { SEVERITY_LABEL, severityFill, severityText } from '@/lib/severity-styles';
import { cn } from '@/lib/utils';

type StigRow = StigRule & Record<string, unknown>;
type ControlRow = ControlCoverage & Record<string, unknown>;

function normCat(cat: string): 'I' | 'II' | 'III' {
  const c = cat.replace(/^CAT\s*/i, '').toUpperCase();
  if (c === '1' || c === 'I') return 'I';
  if (c === '3' || c === 'III') return 'III';
  return 'II';
}

function offenderList(o: StigRule['offenders']): string[] {
  if (typeof o === 'number') return [];
  return o.map((x) => (typeof x === 'string' ? x : `${(x as StigOffender).namespace}/${(x as StigOffender).name}${(x as StigOffender).container ? ` (${(x as StigOffender).container})` : ''}`));
}
function offenderCount(o: StigRule['offenders']): number {
  return typeof o === 'number' ? o : o.length;
}

const CAT_TONE = {
  I: 'border-destructive-foreground bg-destructive-foreground text-canvas',
  II: 'border-destructive-foreground/40 bg-destructive text-destructive-foreground',
  III: 'border-warning-foreground/40 bg-warning text-warning-foreground',
} as const;

const stigColumns: DataTableColumnDef<StigRow>[] = [
  {
    id: 'vulnId',
    accessorFn: (r) => `${r.vulnId} ${r.ruleId} ${r.title}`,
    header: 'Rule',
    filterFn: 'includesString',
    sortFn: 'text',
    cell: ({ row }) => (
      <span className="flex max-w-[460px] flex-col">
        <span className="font-medium">{row.original.title}</span>
        <span className="font-mono text-muted-foreground text-xs">
          {row.original.vulnId} · {row.original.ruleId}
        </span>
      </span>
    ),
  },
  {
    id: 'cat',
    accessorFn: (r) => normCat(String(r.cat)).length,
    header: 'CAT',
    cell: ({ row }) => {
      const c = normCat(String(row.original.cat));
      return <Badge variant="secondary" className={cn('border font-mono', CAT_TONE[c])}>CAT {c}</Badge>;
    },
  },
  { id: 'status', accessorFn: (r) => String(r.status), header: 'Status', sortFn: 'text', cell: ({ row }) => <StatusBadge status={String(row.original.status)} /> },
  {
    id: 'offenders',
    accessorFn: (r) => offenderCount(r.offenders),
    header: 'Offenders',
    cell: ({ row }) => {
      const list = offenderList(row.original.offenders);
      const n = offenderCount(row.original.offenders);
      if (!n) return <span className="text-muted-foreground">—</span>;
      return (
        <Tooltip>
          <TooltipTrigger render={<span />} tabIndex={0} className="cursor-default underline decoration-dotted underline-offset-4 tabular-nums">
            {n} workload{n === 1 ? '' : 's'}
          </TooltipTrigger>
          {list.length ? (
            <TooltipContent className="max-w-80">
              <ul className="text-xs">
                {list.slice(0, 12).map((o) => (
                  <li key={o}>{o}</li>
                ))}
                {list.length > 12 ? <li>…and {list.length - 12} more</li> : null}
              </ul>
            </TooltipContent>
          ) : null}
        </Tooltip>
      );
    },
  },
  {
    id: 'checkId',
    accessorFn: (r) => r.checkId ?? '',
    header: 'Posture check',
    sortFn: 'text',
    cell: ({ row }) =>
      row.original.checkId ? (
        <Link to={`/checks/${encodeURIComponent(row.original.checkId)}`} className="font-mono text-xs underline-offset-4 hover:underline">
          {row.original.checkId}
        </Link>
      ) : (
        <span className="text-muted-foreground text-xs">manual review</span>
      ),
  },
];

const controlColumns: DataTableColumnDef<ControlRow>[] = [
  {
    id: 'control',
    accessorFn: (c) => `${c.control} ${c.title}`,
    header: 'Control',
    filterFn: 'includesString',
    sortFn: 'text',
    cell: ({ row }) => (
      <span className="flex items-center gap-2">
        <Badge variant="outline" className="font-mono">{row.original.control}</Badge>
        <span>{row.original.title}</span>
      </span>
    ),
  },
  { id: 'findingsOpen', accessorFn: (c) => c.findingsOpen, header: 'Open findings', cell: ({ row }) => <span className={cn('tabular-nums', row.original.findingsOpen ? 'text-destructive-foreground' : 'text-muted-foreground')}>{row.original.findingsOpen.toLocaleString()}</span> },
  { id: 'checksFailed', accessorFn: (c) => c.checksFailed, header: 'Failed checks', cell: ({ row }) => <span className={cn('tabular-nums', row.original.checksFailed ? 'text-destructive-foreground' : 'text-muted-foreground')}>{row.original.checksFailed.toLocaleString()}</span> },
  { id: 'status', accessorFn: (c) => c.status, header: 'Status', sortFn: 'text', cell: ({ row }) => <StatusBadge status={row.original.status} /> },
];

const SLA_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

export function CompliancePage() {
  const summary = useSummary();
  const stig = useStig();
  const controls = useControls();
  const rules = stig.data ?? [];
  const openBy = (cat: 'I' | 'II' | 'III') => rules.filter((r) => r.status === 'Open' && normCat(String(r.cat)) === cat).length;
  const counts = {
    open: rules.filter((r) => r.status === 'Open').length,
    naf: rules.filter((r) => r.status === 'NotAFinding').length,
    nr: rules.filter((r) => r.status === 'Not_Reviewed').length,
  };

  return (
    <>
      <PageHeader title="Compliance" description="NIST 800-53 control coverage, Kubernetes STIG rollup and remediation SLA status for the latest scan." />

      <section aria-labelledby="sla-heading" className="flex flex-col gap-3">
        <h2 id="sla-heading" className="flex items-center gap-2 font-medium text-base">
          <Clock className="size-4" /> Past remediation SLA
        </h2>
        {summary.error ? <ErrorAlert error={summary.error} onRetry={() => void summary.refetch()} /> : null}
        {summary.isLoading ? (
          <CardsSkeleton count={4} className="xl:grid-cols-4" />
        ) : (
          <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
            {SLA_SEVERITIES.map((s) => {
              const n = summary.data?.slaOverdue?.[s] ?? 0;
              return (
                <Card key={s} size="sm" className="relative">
                  <span className={cn('absolute inset-y-0 left-0 w-1', n ? severityFill[s] : 'bg-success-foreground')} aria-hidden="true" />
                  <CardContent className="flex flex-col gap-1 pl-5">
                    <span className="text-muted-foreground text-xs uppercase tracking-wide">{SEVERITY_LABEL[s]} overdue</span>
                    <span className={cn('font-semibold text-3xl tabular-nums', n ? severityText[s] : 'text-success-foreground')}>{n}</span>
                    <span className="text-muted-foreground text-xs">of {summary.data?.counts[s] ?? 0} open {SEVERITY_LABEL[s].toLowerCase()} findings</span>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </section>

      <Card>
        <CardHeader>
          <CardTitle>Kubernetes STIG</CardTitle>
          <CardDescription>
            {counts.open} open · {counts.naf} not a finding · {counts.nr} not reviewed — posture checks mapped to DISA Kubernetes STIG / Container Platform SRG rules.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="grid grid-cols-3 gap-3">
            {(['I', 'II', 'III'] as const).map((c) => (
              <div key={c} className="flex items-center justify-between rounded-md border border-border bg-background p-3">
                <span className="flex flex-col">
                  <span className="text-muted-foreground text-xs">CAT {c} open</span>
                  <span className="font-semibold text-2xl tabular-nums">{stig.isLoading ? '…' : openBy(c)}</span>
                </span>
                <Badge variant="secondary" className={cn('border font-mono', CAT_TONE[c])}>CAT {c}</Badge>
              </div>
            ))}
          </div>
          <DataTable<StigRow>
            ariaLabel="STIG rules"
            columns={stigColumns}
            data={asRows(rules)}
            getRowId={(r) => r.vulnId}
            filterColumnId="vulnId"
            filterPlaceholder="Filter rules…"
            selectable={false}
            initialPageSize={25}
            pageSizeOptions={[25, 50, 100]}
            loading={stig.isLoading}
            error={stig.error ? errorMessage(stig.error) : undefined}
            onRetry={() => void stig.refetch()}
            emptyTitle="No STIG rules"
            emptyDescription="The STIG mapping table is empty."
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>NIST 800-53 control coverage</CardTitle>
          <CardDescription>Open vulnerability findings and failed posture checks tagged to each control.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable<ControlRow>
            ariaLabel="NIST control coverage"
            columns={controlColumns}
            data={asRows(controls.data)}
            getRowId={(c) => c.control}
            filterColumnId="control"
            filterPlaceholder="Filter controls…"
            selectable={false}
            showPagination={false}
            initialPageSize={100}
            loading={controls.isLoading}
            error={controls.error ? errorMessage(controls.error) : undefined}
            onRetry={() => void controls.refetch()}
            emptyTitle="No controls"
            emptyDescription="No control mapping is available."
          />
        </CardContent>
      </Card>
    </>
  );
}
