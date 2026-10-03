import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Clock, ListChecks, Play, ShieldCheck } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router';
import { api } from '@/api/client';
import { useControls, useFamilies, useSettings, useStig, useSummary } from '@/api/queries';
import type { Baseline, Severity, StigOffender, StigRule } from '@/api/types';
import { ControlsTable } from '@/components/controls-table';
import { FamilyRollupChart } from '@/components/family-rollup';
import { CardsSkeleton, ErrorAlert, errorMessage, PageHeader } from '@/components/page';
import { StatusBadge } from '@/components/posture';
import { useUrlState } from '@/components/table-kit';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsIndicator, TabsList, TabsPanel, TabsTab } from '@/components/ui/tabs';
import { toast } from '@/components/ui/toast';
import { applicableTotal, catalogHint, complianceTotals, CONTROL_STATUS_LABEL, rollupFamilies, totalsByStatus } from '@/lib/controls';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumnDef } from '@/components/ui/data-table';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { asRows } from '@/lib/format';
import { SEVERITY_LABEL, severityFill, severityText } from '@/lib/severity-styles';
import { cn } from '@/lib/utils';

type StigRow = StigRule & Record<string, unknown>;

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

const SLA_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

const POLL_MS = 2000;
const RUN_TIMEOUT_MS = 180_000;
const sleep = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));

/**
 * POST /compliance/assertions/run (202) then poll GET /compliance/assertions
 * until every reported `checkedAt` has caught up with the run's start.
 */
async function runAssertionsAndWait() {
  const res = await api.runAssertions();
  const stamp = res?.createdAt ?? res?.startedAt;
  const parsed = stamp ? Date.parse(stamp) : Number.NaN;
  const startedAt = Number.isNaN(parsed) ? Date.now() - 1000 : parsed;
  toast.add({ title: 'Assertion run started', description: 'Evaluating control assertions against live cluster state…', type: 'info' });
  const deadline = Date.now() + RUN_TIMEOUT_MS;
  while (Date.now() < deadline) {
    await sleep(POLL_MS);
    const list = await api.assertions();
    const latest = Math.max(0, ...list.map((a) => Date.parse(a.checkedAt ?? '') || 0));
    if (latest >= startedAt) return { done: true, list };
  }
  return { done: false, list: [] as Awaited<ReturnType<typeof api.assertions>> };
}

/** Tile caption with the full-catalog numbers in a tooltip (also its accessible description). */
function CatalogHint({ hint, children }: { hint: string; children: ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger render={<span />} tabIndex={0} className="w-fit cursor-default text-muted-foreground text-xs underline decoration-dotted underline-offset-4">
        {children}
      </TooltipTrigger>
      <TooltipContent className="max-w-72 text-xs">{hint}</TooltipContent>
    </Tooltip>
  );
}

function useAssertionRun() {
  const queryClient = useQueryClient();
  const run = useMutation({
    mutationFn: runAssertionsAndWait,
    onSuccess: ({ done, list }) => {
      void queryClient.invalidateQueries({ queryKey: ['compliance'] });
      if (!done) {
        toast.add({ title: 'Assertion run still in progress', description: 'Results will appear when the engine finishes.', type: 'warning' });
        return;
      }
      const failed = list.filter((a) => a.status === 'fail').length;
      const passed = list.filter((a) => a.status === 'pass').length;
      toast.add({ title: 'Assertions evaluated', description: `${passed} pass · ${failed} fail · ${list.length - passed - failed} unknown or n/a`, type: failed ? 'warning' : 'success' });
    },
    onError: (e) => toast.add({ title: 'Assertion run failed', description: errorMessage(e), type: 'error' }),
  });
  return { start: () => run.mutate(), running: run.isPending };
}

const TABS = ['controls', 'stig', 'sla'] as const;

function ControlsTab() {
  const controls = useControls();
  const families = useFamilies();
  const settings = useSettings();
  const [state, update] = useUrlState({ tab: 'controls', family: '', status: '', baseline: '', q: '' });
  const list = controls.data ?? [];
  const baseline = (families.data?.baseline ?? settings.data?.controlsEngine?.baseline ?? 'moderate') as Baseline;
  const rollup = families.data?.items.length ? families.data.items : rollupFamilies(list.filter((c) => c.inBaseline ?? true));
  // every tile uses the selected baseline; the full-catalog figure is in the tooltip
  const totals = families.data?.totals ?? complianceTotals(list, baseline);
  const inB = totals.baseline;
  const inBCounts = totalsByStatus(inB);
  const loading = controls.isLoading && families.isLoading;

  return (
    <div className="flex flex-col gap-4 pt-2">
      {controls.error ? <ErrorAlert error={controls.error} onRetry={() => void controls.refetch()} /> : null}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <Card size="sm" data-testid="tile-implemented">
          <CardContent className="flex flex-col gap-1">
            <span className="text-muted-foreground text-xs uppercase tracking-wide">Implemented ({baseline} baseline)</span>
            <span className="font-semibold text-3xl tabular-nums">
              {loading ? '…' : inB.implemented}
              <span className="font-normal text-base text-muted-foreground">/{applicableTotal(inB)}</span>
            </span>
            <CatalogHint hint={catalogHint(totals.catalog, inB.total, 'implemented')}>+ {inB.inherited} inherited from the organization</CatalogHint>
          </CardContent>
        </Card>
        {(['partial', 'not-implemented', 'unknown'] as const).map((s) => (
          <Card key={s} size="sm" data-testid={`tile-${s}`}>
            <CardContent className="flex flex-col gap-1">
              <span className="text-muted-foreground text-xs uppercase tracking-wide">
                {CONTROL_STATUS_LABEL[s]} ({baseline} baseline)
              </span>
              <button type="button" className="w-fit rounded-sm text-left outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring" onClick={() => update({ status: s, family: '', baseline })}>
                <span className="font-semibold text-3xl tabular-nums">{loading ? '…' : inBCounts[s]}</span>
              </button>
              <CatalogHint hint={catalogHint(totals.catalog, inB.total, s)}>
                of {inB.total} {baseline} baseline controls
              </CatalogHint>
            </CardContent>
          </Card>
        ))}
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Status by control family</CardTitle>
          <CardDescription>NIST SP 800-53 rev5 families. Click a family or a segment to filter the catalog.</CardDescription>
        </CardHeader>
        <CardContent>
          {controls.isLoading && families.isLoading ? <CardsSkeleton count={1} className="sm:grid-cols-1 xl:grid-cols-1" /> : <FamilyRollupChart families={rollup} selectedFamily={state.family || undefined} onSelect={(family, status) => update({ family, status: status ?? '' })} />}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Control catalog</CardTitle>
          <CardDescription>Implementation status per control with live assertion evidence. Expand a row for the assertions behind it.</CardDescription>
        </CardHeader>
        <CardContent>
          <ControlsTable controls={list} loading={controls.isLoading} filter={state} onFilterChange={(patch) => update(patch)} />
        </CardContent>
      </Card>
    </div>
  );
}

function StigTab() {
  const stig = useStig();
  const rules = stig.data ?? [];
  const openBy = (cat: 'I' | 'II' | 'III') => rules.filter((r) => r.status === 'Open' && normCat(String(r.cat)) === cat).length;
  const counts = {
    open: rules.filter((r) => r.status === 'Open').length,
    naf: rules.filter((r) => r.status === 'NotAFinding').length,
    nr: rules.filter((r) => r.status === 'Not_Reviewed').length,
  };
  return (
    <Card className="mt-2">
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
  );
}

function SlaTab() {
  const summary = useSummary();
  return (
    <section aria-labelledby="sla-heading" className="flex flex-col gap-3 pt-2">
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
  );
}

export function CompliancePage() {
  const [params, setParams] = useSearchParams();
  const tabParam = params.get('tab') ?? 'controls';
  const tab = (TABS as readonly string[]).includes(tabParam) ? tabParam : 'controls';
  // switching tabs drops the controls-table filters
  const setTab = (v: string) => setParams(v === 'controls' ? {} : { tab: v }, { replace: true });
  const run = useAssertionRun();

  return (
    <>
      <PageHeader
        title="Compliance"
        description="NIST 800-53 control implementation with live evidence, Kubernetes STIG rollup and remediation SLA status."
        actions={
          <Button variant="outline" onClick={run.start} loading={run.running} loadingText="Running assertions…">
            <Play />
            Run assertions
          </Button>
        }
      />
      <Tabs value={tab} onValueChange={(v) => setTab(String(v))}>
        <TabsList variant="underline" aria-label="Compliance sections">
          <TabsTab value="controls">
            <ShieldCheck /> Controls
          </TabsTab>
          <TabsTab value="stig">
            <ListChecks /> STIG
          </TabsTab>
          <TabsTab value="sla">
            <Clock /> SLA
          </TabsTab>
          <TabsIndicator />
        </TabsList>
        <TabsPanel value="controls">
          <ControlsTab />
        </TabsPanel>
        <TabsPanel value="stig">
          <StigTab />
        </TabsPanel>
        <TabsPanel value="sla">
          <SlaTab />
        </TabsPanel>
      </Tabs>
    </>
  );
}
