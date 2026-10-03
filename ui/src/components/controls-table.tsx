import { ChevronRight, SearchX, ShieldQuestion } from 'lucide-react';
import { Fragment, useState } from 'react';
import type { ControlAssertion, ControlCoverage } from '@/api/types';
import { BASELINES } from '@/api/types';
import { EmptyState } from '@/components/page';
import { BaselineBadge, StatusBadge } from '@/components/posture';
import { SimpleSelect } from '@/components/simple-select';
import { Pager, SearchInput, SkeletonRows, SortableHead, StateRow, Toolbar } from '@/components/table-kit';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { CodeBlock, CodeBlockBody } from '@/components/ui/code-block';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import {
  CONTROL_STATUS_LABEL,
  CONTROL_STATUSES,
  compareControlId,
  type ControlFilter,
  FAMILY_TITLES,
  familyOf,
  filterControls,
  lowestBaseline,
  normalizeControlStatus,
} from '@/lib/controls';
import { formatDateTime, formatRelative } from '@/lib/format';
import { cn } from '@/lib/utils';

const COLS = 8;
const STATUS_ORDER = Object.fromEntries(CONTROL_STATUSES.map((s, i) => [s, i]));
const BASELINE_ORDER: Record<string, number> = { low: 0, moderate: 1, high: 2 };

function sortKey(c: ControlCoverage, field: string): string | number {
  switch (field) {
    case 'family':
      return familyOf(c);
    case 'baseline':
      return BASELINE_ORDER[lowestBaseline(c.baseline) ?? ''] ?? 9;
    case 'status':
      return STATUS_ORDER[normalizeControlStatus(c.status)];
    case 'findingsOpen':
      return c.findingsOpen ?? 0;
    case 'checksFailed':
      return c.checksFailed ?? 0;
    case 'assertions':
      return c.assertions?.length ?? 0;
    default:
      return 0;
  }
}

export function sortControls(controls: ControlCoverage[], field: string, order: 'asc' | 'desc'): ControlCoverage[] {
  const dir = order === 'asc' ? 1 : -1;
  return [...controls].sort((a, b) => {
    if (field === 'control') return compareControlId(a.control, b.control) * dir;
    const ka = sortKey(a, field);
    const kb = sortKey(b, field);
    return (ka < kb ? -1 : ka > kb ? 1 : 0) * dir || compareControlId(a.control, b.control);
  });
}

/** One-line evidence summary: `detail`, else a compact rendering of the evidence object. */
export function evidenceLine(a: ControlAssertion): string {
  if (a.detail) return a.detail;
  const e = a.evidence;
  if (e === null || e === undefined) return '—';
  if (typeof e === 'string') return e;
  if (typeof e !== 'object') return String(e);
  return Object.entries(e as Record<string, unknown>)
    .slice(0, 4)
    .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
    .join(' · ');
}

function safeJson(v: unknown): string {
  try {
    return JSON.stringify(v ?? null, null, 2);
  } catch {
    return String(v);
  }
}

function AssertionList({ control }: { control: ControlCoverage }) {
  const assertions = control.assertions ?? [];
  if (!assertions.length) {
    const status = normalizeControlStatus(control.status);
    return (
      <p className="text-muted-foreground text-sm">
        {status === 'inherited'
          ? 'Inherited: implemented by the organization or the underlying platform per its component definition; no live assertion.'
          : status === 'not-applicable'
            ? 'Tailored out of the selected baseline.'
            : 'No automated assertion maps to this control; evidence must be supplied manually.'}
        {control.components?.length ? ` Components: ${control.components.join(', ')}.` : ''}
      </p>
    );
  }
  return (
    <ul className="flex flex-col divide-y divide-border" aria-label={`Assertions for ${control.control}`}>
      {assertions.map((a) => (
        <li key={a.id} className="flex flex-col gap-1.5 py-2.5 first:pt-0 last:pb-0">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <StatusBadge status={String(a.status)} />
            <span className="font-medium text-sm">{a.title}</span>
            <span className="font-mono text-muted-foreground text-xs">{a.id}</span>
            <span className="ml-auto text-muted-foreground text-xs" title={formatDateTime(a.checkedAt)}>
              checked {formatRelative(a.checkedAt)}
            </span>
          </div>
          <p className="line-clamp-1 text-muted-foreground text-xs" title={evidenceLine(a)}>
            {evidenceLine(a)}
          </p>
          {a.evidence !== undefined && a.evidence !== null ? (
            <details className="group">
              <summary className="w-fit cursor-pointer select-none rounded-sm text-muted-foreground text-xs underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring">
                Raw evidence
              </summary>
              <CodeBlock code={safeJson(a.evidence)} className="mt-2 w-full text-xs">
                <CodeBlockBody maxLines={16} aria-label={`Raw evidence for ${a.id}`} />
              </CodeBlock>
            </details>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

export function ControlsTable({
  controls,
  loading,
  filter,
  onFilterChange,
}: {
  controls: ControlCoverage[];
  loading?: boolean;
  filter: ControlFilter;
  onFilterChange: (patch: Partial<ControlFilter>) => void;
}) {
  const [sort, setSort] = useState<{ field: string; order: 'asc' | 'desc' }>({ field: 'control', order: 'asc' });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());

  const families = [...new Set(controls.map((c) => familyOf(c)))].sort();
  const filtered = sortControls(filterControls(controls, filter), sort.field, sort.order);
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const current = Math.min(page, pages);
  const rows = filtered.slice((current - 1) * pageSize, current * pageSize);
  const isFiltered = Boolean(filter.q || filter.family || filter.status || filter.baseline);

  const update = (patch: Partial<ControlFilter>) => {
    setPage(1);
    onFilterChange(patch);
  };
  const onSort = (field: string, order: 'asc' | 'desc') => setSort({ field, order });
  const toggle = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <div className="flex flex-col gap-4">
      <Toolbar>
        <SearchInput label="Search controls" placeholder="Search id, title, component…" value={filter.q ?? ''} onChange={(q) => update({ q })} />
        <SimpleSelect
          ariaLabel="Family"
          allLabel="All families"
          className="w-48"
          value={filter.family ?? ''}
          onChange={(family) => update({ family })}
          options={families.map((f) => ({ value: f, label: `${f} · ${FAMILY_TITLES[f] ?? f}` }))}
        />
        <SimpleSelect
          ariaLabel="Status"
          allLabel="Any status"
          className="w-44"
          value={filter.status ?? ''}
          onChange={(status) => update({ status })}
          options={CONTROL_STATUSES.map((s) => ({ value: s, label: CONTROL_STATUS_LABEL[s] }))}
        />
        <SimpleSelect
          ariaLabel="Baseline"
          allLabel="Any baseline"
          value={filter.baseline ?? ''}
          onChange={(baseline) => update({ baseline })}
          options={BASELINES.map((b) => ({ value: b, label: `${b[0].toUpperCase()}${b.slice(1)} baseline` }))}
        />
        {isFiltered ? (
          <Button variant="ghost" size="sm" onClick={() => update({ q: '', family: '', status: '', baseline: '' })}>
            Clear filters
          </Button>
        ) : null}
      </Toolbar>

      <Table aria-label="Control catalog" aria-busy={loading || undefined}>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <SortableHead label="Control" field="control" sort={sort.field} order={sort.order} onSort={onSort} />
            <SortableHead label="Family" field="family" sort={sort.field} order={sort.order} onSort={onSort} />
            <SortableHead label="Baseline" field="baseline" sort={sort.field} order={sort.order} onSort={onSort} />
            <SortableHead label="Status" field="status" sort={sort.field} order={sort.order} onSort={onSort} />
            <TableHead className="px-3">Components</TableHead>
            <SortableHead label="Assertions" field="assertions" sort={sort.field} order={sort.order} onSort={onSort} />
            <SortableHead label="Findings" field="findingsOpen" sort={sort.field} order={sort.order} onSort={onSort} />
            <SortableHead label="Checks" field="checksFailed" sort={sort.field} order={sort.order} onSort={onSort} />
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading ? (
            <SkeletonRows cols={COLS} />
          ) : rows.length === 0 ? (
            <StateRow cols={COLS}>
              {isFiltered ? (
                <EmptyState icon={<SearchX className="size-6" />} title="No controls match these filters">
                  Try a different search or clear your filters.
                </EmptyState>
              ) : (
                <EmptyState icon={<ShieldQuestion className="size-6" />} title="No controls">
                  The control evidence engine hasn’t reported a catalog yet.
                </EmptyState>
              )}
            </StateRow>
          ) : (
            rows.map((c) => {
              const open = expanded.has(c.control);
              const status = normalizeControlStatus(c.status);
              const passing = (c.assertions ?? []).filter((a) => a.status === 'pass').length;
              const panelId = `control-${c.control.replace(/[^A-Za-z0-9]/g, '-')}-evidence`;
              return (
                <Fragment key={c.control}>
                  <TableRow data-state={open ? 'selected' : undefined} data-control={c.control}>
                    <TableCell className="px-3 py-2">
                      <span className="flex items-center gap-1.5">
                        <Button
                          size="icon-xs"
                          variant="ghost"
                          aria-expanded={open}
                          aria-controls={open ? panelId : undefined}
                          aria-label={`${open ? 'Hide' : 'Show'} evidence for ${c.control}`}
                          onClick={() => toggle(c.control)}
                        >
                          <ChevronRight className={cn('motion-safe:transition-transform', open && 'rotate-90')} />
                        </Button>
                        <Badge variant="outline" className="font-mono">
                          {c.control}
                        </Badge>
                        <span className="max-w-[220px] truncate" title={c.title}>
                          {c.title}
                        </span>
                      </span>
                    </TableCell>
                    <TableCell className="px-3 py-2 font-mono text-xs" title={FAMILY_TITLES[familyOf(c)]}>
                      {familyOf(c)}
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <BaselineBadge baseline={lowestBaseline(c.baseline)} />
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <StatusBadge status={status} />
                    </TableCell>
                    <TableCell className="max-w-[160px] px-3 py-2">
                      {c.components?.length ? (
                        <span className="line-clamp-2 text-xs" title={c.components.join(', ')}>
                          {c.components.join(', ')}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="px-3 py-2 text-xs tabular-nums">
                      {c.assertions?.length ? (
                        <span>
                          <span className={passing === c.assertions.length ? 'text-success-foreground' : 'text-foreground'}>{passing}</span>
                          <span className="text-muted-foreground">/{c.assertions.length} pass</span>
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className={cn('px-3 py-2 text-right tabular-nums', c.findingsOpen ? 'text-destructive-foreground' : 'text-muted-foreground')}>
                      {(c.findingsOpen ?? 0).toLocaleString()}
                    </TableCell>
                    <TableCell className={cn('px-3 py-2 text-right tabular-nums', c.checksFailed ? 'text-destructive-foreground' : 'text-muted-foreground')}>
                      {(c.checksFailed ?? 0).toLocaleString()}
                    </TableCell>
                  </TableRow>
                  {open ? (
                    <TableRow className="bg-muted/40 hover:bg-muted/40">
                      <TableCell colSpan={COLS} className="px-4 py-3 whitespace-normal" id={panelId}>
                        <AssertionList control={c} />
                      </TableCell>
                    </TableRow>
                  ) : null}
                </Fragment>
              );
            })
          )}
        </TableBody>
      </Table>
      {!loading && filtered.length > 0 ? (
        <Pager
          page={current}
          pageSize={pageSize}
          total={filtered.length}
          onPage={setPage}
          onPageSize={(n) => {
            setPageSize(n);
            setPage(1);
          }}
          pageSizeOptions={[25, 50, 100]}
        />
      ) : null}
    </div>
  );
}
