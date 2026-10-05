import { ChevronDown, ChevronRight, FileQuestion, SearchX, TriangleAlert } from 'lucide-react';
import { Fragment, useState } from 'react';
import { ApiError } from '@/api/client';
import { useImageStig } from '@/api/queries';
import type { ImageStigBenchmark, ImageStigQuery } from '@/api/types';
import { CardsSkeleton, EmptyState, ErrorAlert, Meta } from '@/components/page';
import { GradeRing } from '@/components/posture';
import { SimpleSelect } from '@/components/simple-select';
import { CatBadge, CatOpenChips, ResultBadge, SourceBadge, StigResultBar } from '@/components/stig';
import { Pager, SearchInput, SkeletonRows, StateRow, Toolbar } from '@/components/table-kit';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsList, TabsTab } from '@/components/ui/tabs';
import { formatRelative } from '@/lib/format';
import { CAT_LABEL, fidelityDegraded, normResult, RESULT_LABEL, stigGrade, stigStateTooltip } from '@/lib/stig';

const RESULT_FILTER = (['fail', 'pass', 'error', 'notchecked', 'notapplicable', 'informational', 'unknown'] as const).map((r) => ({ value: r, label: RESULT_LABEL[r] }));
const CAT_FILTER = (['cat1', 'cat2', 'cat3'] as const).map((c) => ({ value: c, label: CAT_LABEL[c] }));
const PAGE_SIZES = [25, 50, 100, 250];

type Query = Required<Pick<ImageStigQuery, 'page' | 'pageSize'>> & Omit<ImageStigQuery, 'page' | 'pageSize' | 'benchmark'>;
const DEFAULT_QUERY: Query = { page: 1, pageSize: 50 };

function BenchmarkHeader({ b, degraded, warnings }: { b: ImageStigBenchmark; degraded: boolean; warnings: string[] }) {
  const s = b.summary;
  // per-CAT open counts: from the summary, or from the rules when the whole benchmark is on this page
  const unpaged = !b.rulesTotal || b.rules.length >= b.rulesTotal;
  const openFromRules = (c: 'cat1' | 'cat2' | 'cat3') => (unpaged ? b.rules.filter((r) => normResult(r.result) === 'fail' && r.severity === c).length : undefined);
  return (
    <div className="flex flex-col gap-3">
      {degraded ? (
        <Alert variant="warning">
          <TriangleAlert />
          <AlertTitle>Rootfs extraction was degraded</AlertTitle>
          <AlertDescription>
            Ownership, mode or extended attributes could not be fully preserved when flattening this image, so file-permission rules may be inaccurate.
            {warnings.length ? (
              <ul className="mt-1 list-disc pl-4">
                {warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            ) : null}
          </AlertDescription>
        </Alert>
      ) : null}
      <div className="flex flex-col gap-4 rounded-md border border-border bg-background p-4 md:flex-row md:items-center">
        <div className="flex shrink-0 flex-col items-center gap-1">
          <GradeRing score={s.score} grade={stigGrade(s.score)} size={96} stroke={9} />
          <span className="text-muted-foreground text-xs">STIG score</span>
        </div>
        <div className="flex min-w-0 flex-1 flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-semibold text-base">{b.title}</h3>
            {b.version ? <Badge variant="outline" className="font-mono">{b.version}</Badge> : null}
            <SourceBadge source={b.source} />
          </div>
          <div className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-3">
            <Meta label="Profile">
              <code className="break-all text-xs">{b.profileId || '—'}</code>
            </Meta>
            <Meta label="Benchmark id">
              <code className="break-all text-xs">{b.benchmarkId}</code>
            </Meta>
            <Meta label="Evaluated">{formatRelative(b.checkedAt ?? null)}</Meta>
          </div>
          <StigResultBar counts={s} />
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground text-xs">Open</span>
            <CatOpenChips cat1={s.cat1Open ?? openFromRules('cat1')} cat2={s.cat2Open ?? openFromRules('cat2')} cat3={s.cat3Open ?? openFromRules('cat3')} />
          </div>
        </div>
      </div>
    </div>
  );
}

function RuleTable({ b, query, onQuery, loading }: { b: ImageStigBenchmark; query: Query; onQuery: (patch: Partial<Query>) => void; loading: boolean }) {
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const filtered = Boolean(query.q || query.result || query.severity);
  const COLS = 6;
  return (
    <div className="flex flex-col gap-3">
      <Toolbar>
        <SearchInput label="Search rules" placeholder="Search title, V-ID, CCI…" value={query.q ?? ''} onChange={(v) => onQuery({ q: v || undefined })} />
        <SimpleSelect ariaLabel="Result" allLabel="All results" value={query.result ?? ''} onChange={(v) => onQuery({ result: v || undefined })} options={RESULT_FILTER} />
        <SimpleSelect ariaLabel="Category" allLabel="All categories" value={query.severity ?? ''} onChange={(v) => onQuery({ severity: v || undefined })} options={CAT_FILTER} />
        {filtered ? (
          <Button variant="ghost" size="sm" onClick={() => onQuery({ q: undefined, result: undefined, severity: undefined })}>
            Clear filters
          </Button>
        ) : null}
      </Toolbar>
      <Table aria-label="STIG rules" aria-busy={loading || undefined}>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="w-8 px-2" aria-label="Fix text" />
            <TableHead className="px-3">Result</TableHead>
            <TableHead className="px-3">CAT</TableHead>
            <TableHead className="px-3">V-ID</TableHead>
            <TableHead className="px-3">Title</TableHead>
            <TableHead className="px-3">CCIs</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading ? (
            <SkeletonRows cols={COLS} rows={Math.min(query.pageSize, 8)} />
          ) : b.rules.length === 0 ? (
            <StateRow cols={COLS}>
              <EmptyState icon={<SearchX className="size-6" />} title={filtered ? 'No rules match' : 'No rules'}>
                {filtered ? 'Clear the filters to see every rule.' : 'This benchmark reported no rule results.'}
              </EmptyState>
            </StateRow>
          ) : (
            b.rules.map((r) => {
              const expanded = open.has(r.ruleId);
              return (
                <Fragment key={r.ruleId}>
                  <TableRow data-result={r.result}>
                    <TableCell className="px-2 py-2">
                      {r.fixText ? (
                        <Button size="icon-xs" variant="ghost" aria-expanded={expanded} aria-label={`${expanded ? 'Hide' : 'Show'} fix text for ${r.stigId ?? r.ruleId}`} onClick={() => toggle(r.ruleId)}>
                          {expanded ? <ChevronDown /> : <ChevronRight />}
                        </Button>
                      ) : null}
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <ResultBadge result={String(r.result)} />
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <CatBadge cat={r.severity} />
                    </TableCell>
                    <TableCell className="whitespace-nowrap px-3 py-2 font-mono text-xs">{r.stigId ?? <span className="text-muted-foreground">—</span>}</TableCell>
                    <TableCell className="max-w-[560px] whitespace-normal px-3 py-2">
                      <span className="block">{r.title}</span>
                      <code className="block truncate text-[11px] text-muted-foreground" title={r.ruleId}>
                        {r.ruleId}
                      </code>
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <span className="flex flex-wrap gap-1">
                        {r.cci.length ? r.cci.map((c) => <Badge key={c} variant="outline" className="font-mono text-[10px]">{c}</Badge>) : <span className="text-muted-foreground">—</span>}
                      </span>
                    </TableCell>
                  </TableRow>
                  {expanded ? (
                    <TableRow className="hover:bg-transparent">
                      <TableCell colSpan={COLS} className="bg-muted/40 px-10 py-3">
                        <span className="mb-1 block text-[11px] text-muted-foreground uppercase tracking-wide">Fix text</span>
                        <p className="whitespace-pre-wrap text-sm">{r.fixText}</p>
                      </TableCell>
                    </TableRow>
                  ) : null}
                </Fragment>
              );
            })
          )}
        </TableBody>
      </Table>
      {b.rulesTotal > 0 ? (
        <Pager page={query.page} pageSize={query.pageSize} total={b.rulesTotal} onPage={(page) => onQuery({ page })} onPageSize={(pageSize) => onQuery({ pageSize })} pageSizeOptions={PAGE_SIZES} />
      ) : null}
    </div>
  );
}

/** The stored result is the previous one: the last re-evaluation failed transiently. */
function StaleAlert({ error, since }: { error?: string | null; since?: string | null }) {
  return (
    <Alert variant="warning" data-testid="stig-stale-alert">
      <TriangleAlert />
      <AlertTitle>Showing the previous STIG evaluation</AlertTitle>
      <AlertDescription>
        The last re-evaluation{since ? ` (since ${formatRelative(since)})` : ''} failed{error ? `: ${error}` : ''}. The previous result is kept until a genuine
        evaluation replaces it; the next scan retries.
      </AlertDescription>
    </Alert>
  );
}

/** Image-level outcome without benchmark results (`status` from `GET /images/{id}/stig`). */
function NoBenchmark({ status, reason }: { status?: string | null; reason?: string | null }) {
  const icon = <FileQuestion className="size-6" />;
  switch (status) {
    case 'error':
    case 'timeout':
      return (
        <EmptyState icon={icon} title={status === 'timeout' ? 'SCAP evaluation timed out' : 'SCAP evaluation failed'}>
          {reason ?? 'The scap-worker could not evaluate this image.'} The next scan retries it.
        </EmptyState>
      );
    case 'notEvaluated':
    case 'pending':
    case 'queued':
    case 'running':
      return (
        <div title={stigStateTooltip('notEvaluated')} data-stig-state="notEvaluated">
          <EmptyState icon={icon} title="Not evaluated yet">
            The SCAP stage hasn’t evaluated this image yet. It runs after the image is scanned while the SCAP scanner is enabled; this is not the same as “not
            applicable”.
          </EmptyState>
        </div>
      );
    case 'noContent':
      return (
        <div title={stigStateTooltip('noContent')} data-stig-state="noContent">
          <EmptyState icon={icon} title="No SCAP content for this image">
            {reason ?? 'The operating system or product was detected, but no benchmark for it is in the content catalogue.'} Add a content source in the Helm
            values to evaluate it.
          </EmptyState>
        </div>
      );
    default:
      return (
        <div title={stigStateTooltip('notApplicable')} data-stig-state="notApplicable">
          <EmptyState icon={icon} title="No applicable benchmark">
            {reason ?? 'No SCAP content in the catalogue matches this image’s operating system or products.'} That is an accepted result: the image is reported as
            not applicable.
          </EmptyState>
        </div>
      );
  }
}

/** Image detail → STIG tab (§14): one sub-tab per applicable benchmark, rules paged server-side. */
export function ImageStigTab({ imageId }: { imageId: string }) {
  const [query, setQuery] = useState<Query>(DEFAULT_QUERY);
  // the selected benchmark stays client-side: the API pages every benchmark's rules alike, and
  // `?benchmark=` would drop the other benchmarks (and their sub-tabs) from the response
  const [benchmark, setBenchmark] = useState<string | null>(null);
  const onQuery = (patch: Partial<Query>) => setQuery((q) => ({ ...q, ...patch, page: patch.page ?? 1 }));
  const { data, error, isLoading, isPlaceholderData, refetch } = useImageStig(imageId, query);

  if (isLoading) return <CardsSkeleton count={1} className="sm:grid-cols-1 xl:grid-cols-1" />;
  if (error) {
    if (error instanceof ApiError && error.status === 404) {
      return (
        <EmptyState icon={<FileQuestion className="size-6" />} title="No SCAP results">
          The SCAP scanner hasn’t evaluated this image (it may be disabled in Settings → SCAP, or this API version doesn’t provide product STIGs).
        </EmptyState>
      );
    }
    return <ErrorAlert error={error} onRetry={() => void refetch()} />;
  }
  const stale = data?.stig?.stale ? <StaleAlert error={data.stig.staleError} since={data.stig.staleSince} /> : null;
  if (!data?.benchmarks.length) {
    return (
      <div className="flex flex-col gap-4 pt-2">
        {stale}
        <NoBenchmark status={data?.status} reason={data?.reason} />
      </div>
    );
  }
  const selected = data.benchmarks.find((b) => b.benchmarkId === benchmark) ?? data.benchmarks[0];
  const degraded = fidelityDegraded(selected.rootfsFidelity) || (!selected.rootfsFidelity && fidelityDegraded(data.rootfsFidelity));
  const warnings = [...new Set([...(selected.rootfsWarnings ?? []), ...(data.rootfsWarnings ?? [])])];
  const body = (
    <div className="flex flex-col gap-4">
      <BenchmarkHeader b={selected} degraded={degraded} warnings={warnings} />
      <RuleTable key={selected.benchmarkId} b={selected} query={query} onQuery={onQuery} loading={isPlaceholderData} />
    </div>
  );
  return (
    <div className="flex flex-col gap-4 pt-2">
      {stale}
      {data.benchmarks.length > 1 ? (
        <Tabs value={selected.benchmarkId} onValueChange={(v) => {
            setBenchmark(String(v));
            onQuery({});
          }}>
          <TabsList aria-label="Benchmarks">
            {data.benchmarks.map((b) => (
              <TabsTab key={b.benchmarkId} value={b.benchmarkId}>
                {b.title}
                <Badge variant={b.summary.fail ? 'destructive' : 'secondary'}>{b.summary.fail}</Badge>
              </TabsTab>
            ))}
          </TabsList>
        </Tabs>
      ) : null}
      {body}
    </div>
  );
}
