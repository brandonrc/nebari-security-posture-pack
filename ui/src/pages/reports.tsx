import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Download, FilePlus2, PackageCheck, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router';
import { api } from '@/api/client';
import { qk, useNamespaces, useReports, useReportTypes, useSettings, useWorkloads } from '@/api/queries';
import type { Report, ReportCreate, ReportScopeKind, ReportType } from '@/api/types';
import { errorMessage, PageHeader } from '@/components/page';
import { StatusBadge } from '@/components/posture';
import { SimpleSelect } from '@/components/simple-select';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { DataTable, type DataTableColumnDef } from '@/components/ui/data-table';
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { toast } from '@/components/ui/toast';
import { asRows, formatBytes, formatDateTime, formatRelative } from '@/lib/format';

type Row = Report & Record<string, unknown>;

function typeLabel(types: ReportType[] | undefined, type: string) {
  return types?.find((t) => t.type === type)?.title ?? type;
}

function scopeLabel(r: Report) {
  return r.scope.kind === 'cluster' ? 'cluster' : `${r.scope.kind}: ${r.scope.name ?? '—'}`;
}

function GenerateDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const types = useReportTypes();
  const settings = useSettings();
  const namespaces = useNamespaces();
  const workloads = useWorkloads();
  const queryClient = useQueryClient();
  const [typeChoice, setType] = useState('');
  const [formatChoice, setFormat] = useState('');
  const [scopeChoice, setScopeChoice] = useState<ReportScopeKind>('cluster');
  const [scopeName, setScopeName] = useState('');
  const [rollupByCve, setRollupByCve] = useState(false);
  const [includeSystem, setIncludeSystem] = useState(true);
  const [systemNameChoice, setSystemName] = useState<string | null>(null);

  // Derived selections: type → formats/scopes cascade without effects.
  const type = typeChoice || types.data?.[0]?.type || '';
  const selected = types.data?.find((t) => t.type === type);
  const format = selected && selected.formats.includes(formatChoice) ? formatChoice : (selected?.formats[0] ?? '');
  const scopeKind: ReportScopeKind = selected && !selected.scopes.includes(scopeChoice) ? selected.scopes[0] : scopeChoice;
  const setScopeKind = (kind: ReportScopeKind) => {
    setScopeChoice(kind);
    setScopeName('');
  };
  const systemName = systemNameChoice ?? settings.data?.systemName ?? '';

  const create = useMutation({
    mutationFn: (body: ReportCreate) => api.createReport(body),
    onSuccess: (report) => {
      toast.add({ title: 'Report queued', description: `${typeLabel(types.data, report.type)} (${report.format}) for ${scopeLabel(report)}`, type: 'info' });
      void queryClient.invalidateQueries({ queryKey: qk.reports });
      onOpenChange(false);
    },
    onError: (e) => toast.add({ title: 'Could not generate report', description: errorMessage(e), type: 'error' }),
  });

  const nameOptions =
    scopeKind === 'namespace'
      ? (namespaces.data ?? []).map((n) => ({ value: n.name, label: n.name }))
      : (workloads.data ?? []).map((w) => ({ value: `${w.namespace}/${w.kind}/${w.name}`, label: `${w.namespace}/${w.name} (${w.kind})` }));
  const canSubmit = Boolean(type && format && (scopeKind === 'cluster' || scopeName));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Generate report</DialogTitle>
          <DialogDescription>Built from the latest completed scan snapshot. Reports usually take a few seconds.</DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-4 overflow-y-auto"
          onSubmit={(e) => {
            e.preventDefault();
            if (!canSubmit) return;
            create.mutate({
              type,
              format,
              scope: scopeKind === 'cluster' ? { kind: 'cluster' } : { kind: scopeKind, name: scopeName },
              options: {
                ...(type === 'poam' ? { rollupByCve } : {}),
                systemName: systemName || undefined,
                includeSystemNamespaces: includeSystem,
              },
            });
          }}
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <Label>Report type</Label>
              <SimpleSelect ariaLabel="Report type" className="w-full" value={type} onChange={setType} options={(types.data ?? []).map((t) => ({ value: t.type, label: t.title ?? t.type }))} disabled={types.isLoading} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>Format</Label>
              <SimpleSelect ariaLabel="Format" className="w-full" value={format} onChange={setFormat} options={(selected?.formats ?? []).map((f) => ({ value: f, label: f.toUpperCase() }))} disabled={!selected} />
            </div>
          </div>
          {selected ? (
            <p className="rounded-md border border-border bg-muted/40 px-3 py-2 text-muted-foreground text-xs leading-relaxed">
              <span className="font-medium font-mono text-foreground">{selected.type}</span> — {selected.description || 'No description provided.'}
            </p>
          ) : null}
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <Label>Scope</Label>
              <SimpleSelect
                ariaLabel="Scope"
                className="w-full"
                value={scopeKind}
                onChange={(v) => setScopeKind(v as ReportScopeKind)}
                options={(selected?.scopes ?? ['cluster']).map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) }))}
              />
            </div>
            {scopeKind !== 'cluster' ? (
              <div className="flex flex-col gap-1.5">
                <Label>{scopeKind === 'namespace' ? 'Namespace' : 'Workload'}</Label>
                <SimpleSelect ariaLabel={scopeKind === 'namespace' ? 'Namespace' : 'Workload'} className="w-full" value={scopeName} onChange={setScopeName} options={nameOptions} />
              </div>
            ) : null}
          </div>
          <fieldset className="flex flex-col gap-3 rounded-md border border-border p-3">
            <legend className="px-1 font-medium text-sm">Options</legend>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="report-system-name">System name</Label>
              <Input id="report-system-name" value={systemName} onChange={(e) => setSystemName(e.target.value)} placeholder="Defaults to settings" />
            </div>
            {type === 'poam' ? (
              <label className="flex items-center gap-2 text-sm">
                <Switch checked={rollupByCve} onCheckedChange={setRollupByCve} aria-label="Roll up by CVE" />
                Roll up rows per CVE (instead of per image)
              </label>
            ) : null}
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={includeSystem} onCheckedChange={setIncludeSystem} aria-label="Include system namespaces" />
              Include system namespaces (kube-system…)
            </label>
          </fieldset>
          <DialogFooter>
            <DialogClose render={<Button type="button" variant="ghost" />}>Cancel</DialogClose>
            <Button type="submit" disabled={!canSubmit} loading={create.isPending} loadingText="Queuing…">
              <FilePlus2 />
              Generate
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Evidence package (DESIGN §11/§13): POA&M, STIG checklist, automated assessment summary, OSCAL AR +
 * SSP and the draft CRM, all from the same scan and control evidence run. Inputs to an ATO package,
 * not the package itself (compliance review M8).
 */
const COMPLIANCE_PACKAGE: Array<{ type: string; format: string }> = [
  { type: 'poam', format: 'xlsx' },
  { type: 'stig-checklist', format: 'cklb' },
  { type: 'sar', format: 'pdf' },
  { type: 'oscal-ar', format: 'json' },
  { type: 'oscal-ssp', format: 'json' },
  { type: 'crm', format: 'xlsx' },
];

function CompliancePackageButton() {
  const types = useReportTypes();
  const queryClient = useQueryClient();
  const queue = useMutation({
    mutationFn: async () => {
      const catalogue = types.data ?? [];
      const wanted = COMPLIANCE_PACKAGE.filter((p) => catalogue.length === 0 || catalogue.some((t) => t.type === p.type && t.formats.includes(p.format)));
      const skipped = COMPLIANCE_PACKAGE.filter((p) => !wanted.includes(p));
      const results = await Promise.allSettled(wanted.map((p) => api.createReport({ type: p.type, format: p.format, scope: { kind: 'cluster' } })));
      return { results, wanted, skipped };
    },
    onSuccess: ({ results, wanted, skipped }) => {
      void queryClient.invalidateQueries({ queryKey: qk.reports });
      const ok = results.filter((r) => r.status === 'fulfilled').length;
      const failed = results
        .map((r, i) => (r.status === 'rejected' ? `${wanted[i].type} (${errorMessage(r.reason)})` : null))
        .filter(Boolean);
      const notes = [
        ...(failed.length ? [`failed: ${failed.join(', ')}`] : []),
        ...(skipped.length ? [`not offered by the API: ${skipped.map((p) => `${p.type}.${p.format}`).join(', ')}`] : []),
      ];
      toast.add({
        title: ok ? `Evidence package queued (${ok} report${ok === 1 ? '' : 's'})` : 'Evidence package failed',
        description: notes.length
          ? notes.join(' · ')
          : 'POA&M (xlsx), STIG checklist (cklb), automated assessment summary (pdf), OSCAL AR, OSCAL SSP and the draft CRM for the cluster.',
        type: failed.length || skipped.length ? (ok ? 'warning' : 'error') : 'info',
      });
    },
    onError: (e) => toast.add({ title: 'Evidence package failed', description: errorMessage(e), type: 'error' }),
  });
  return (
    <Button variant="outline" onClick={() => queue.mutate()} loading={queue.isPending} loadingText="Queuing…" disabled={types.isLoading} title="Evidence for an assessor: POA&M xlsx + STIG cklb + assessment summary pdf + OSCAL AR + OSCAL SSP + CRM xlsx">
      <PackageCheck />
      Evidence package
    </Button>
  );
}

function DeleteButton({ report }: { report: Report }) {
  const [open, setOpen] = useState(false);
  const queryClient = useQueryClient();
  const del = useMutation({
    mutationFn: () => api.deleteReport(report.id),
    onSuccess: () => {
      queryClient.setQueryData<Report[]>(qk.reports, (prev) => prev?.filter((r) => r.id !== report.id));
      toast.add({ title: 'Report deleted', type: 'success' });
      setOpen(false);
    },
    onError: (e) => toast.add({ title: 'Delete failed', description: errorMessage(e), type: 'error' }),
  });
  return (
    <>
      <Button size="icon-sm" variant="ghost" aria-label={`Delete report ${report.filename ?? report.id}`} onClick={() => setOpen(true)}>
        <Trash2 />
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete report?</DialogTitle>
            <DialogDescription>{report.filename ?? `Report ${report.id}`} will be removed permanently.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose render={<Button variant="ghost" />}>Cancel</DialogClose>
            <Button variant="destructive" onClick={() => del.mutate()} loading={del.isPending}>
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

export function ReportsPage() {
  const { data, error, isLoading, refetch } = useReports();
  const types = useReportTypes();
  const [open, setOpen] = useState(false);
  const previous = useRef<Map<string, string>>(new Map());

  // toast when a report the user is watching finishes
  useEffect(() => {
    if (!data) return;
    for (const r of data) {
      const before = previous.current.get(String(r.id));
      if ((before === 'running' || before === 'queued') && r.status === 'done') {
        toast.add({ title: 'Report ready', description: r.filename ?? `${r.type}.${r.format}`, type: 'success' });
      } else if ((before === 'running' || before === 'queued') && r.status === 'failed') {
        toast.add({ title: 'Report failed', description: r.error ?? undefined, type: 'error' });
      }
      previous.current.set(String(r.id), r.status);
    }
  }, [data]);

  const columns = useMemo<DataTableColumnDef<Row>[]>(
    () => [
      {
        id: 'type',
        accessorFn: (r) => `${typeLabel(types.data, r.type)} ${r.filename ?? ''}`,
        header: 'Report',
        filterFn: 'includesString',
        sortFn: 'text',
        cell: ({ row }) => (
          <span className="flex flex-col">
            <span className="font-medium">{typeLabel(types.data, row.original.type)}</span>
            <span className="max-w-[300px] truncate font-mono text-muted-foreground text-xs">{row.original.filename ?? '—'}</span>
          </span>
        ),
      },
      { id: 'format', accessorFn: (r) => r.format, header: 'Format', sortFn: 'text', cell: ({ row }) => <Badge variant="outline" className="font-mono uppercase">{row.original.format}</Badge> },
      { id: 'scope', accessorFn: (r) => scopeLabel(r), header: 'Scope', sortFn: 'text', cell: ({ row }) => <span className="text-sm">{scopeLabel(row.original)}</span> },
      {
        id: 'scan',
        accessorFn: (r) => Number(r.scanId ?? 0),
        header: 'Scan',
        cell: ({ row }) =>
          row.original.scanId !== null ? (
            <Link to={`/scans/${row.original.scanId}`} className="tabular-nums underline-offset-4 hover:underline">
              #{row.original.scanId}
            </Link>
          ) : (
            '—'
          ),
      },
      {
        id: 'createdAt',
        accessorFn: (r) => r.createdAt,
        header: 'Created',
        sortFn: 'text',
        cell: ({ row }) => (
          <span className="flex flex-col text-xs" title={formatDateTime(row.original.createdAt)}>
            <span>{formatRelative(row.original.createdAt)}</span>
            <span className="text-muted-foreground">{row.original.createdBy ?? ''}</span>
          </span>
        ),
      },
      { id: 'size', accessorFn: (r) => r.sizeBytes ?? -1, header: 'Size', cell: ({ row }) => <span className="tabular-nums">{formatBytes(row.original.sizeBytes)}</span> },
      {
        id: 'status',
        accessorFn: (r) => r.status,
        header: 'Status',
        sortFn: 'text',
        cell: ({ row }) => (
          <span className="flex max-w-[260px] flex-col gap-0.5">
            <StatusBadge status={row.original.status} />
            {row.original.error ? <span className="line-clamp-2 text-destructive-foreground text-xs" title={row.original.error}>{row.original.error}</span> : null}
          </span>
        ),
      },
      {
        id: 'actions',
        header: 'Actions',
        enableHiding: false,
        enableSorting: false,
        cell: ({ row }) => (
          <span className="flex items-center gap-1">
            <Button
              size="sm"
              variant="outline"
              disabled={row.original.status !== 'done'}
              render={row.original.status === 'done' ? <a href={api.reportDownloadUrl(row.original.id)} download={row.original.filename ?? undefined} /> : undefined}
            >
              <Download />
              Download
            </Button>
            <DeleteButton report={row.original} />
          </span>
        ),
      },
    ],
    [types.data],
  );

  return (
    <>
      <PageHeader
        title="Reports"
        description="Evidence for ATO / cATO packages generated from scan snapshots: POA&M, STIG checklists, automated assessment summaries (input to the SAR), OSCAL assessment results, SSP drafts, the draft CRM, component definitions and inventories."
        actions={
          <>
            <CompliancePackageButton />
            <Button onClick={() => setOpen(true)}>
              <FilePlus2 />
              Generate report
            </Button>
          </>
        }
      />
      <Card>
        <CardContent>
          <DataTable<Row>
            ariaLabel="Reports"
            columns={columns}
            data={asRows(data)}
            getRowId={(r) => String(r.id)}
            filterColumnId="type"
            filterPlaceholder="Filter reports…"
            selectable={false}
            initialPageSize={20}
            pageSizeOptions={[20, 50]}
            loading={isLoading}
            error={error ? errorMessage(error) : undefined}
            onRetry={() => void refetch()}
            emptyTitle="No reports yet"
            emptyDescription="Generate a POA&M, STIG checklist or assessment summary from the latest scan."
            emptyAction={
              <Button variant="outline" onClick={() => setOpen(true)}>
                <FilePlus2 />
                Generate report
              </Button>
            }
          />
        </CardContent>
      </Card>
      <GenerateDialog open={open} onOpenChange={setOpen} />
    </>
  );
}
