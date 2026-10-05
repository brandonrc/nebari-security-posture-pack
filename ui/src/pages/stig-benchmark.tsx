import { ChevronDown, ChevronRight, SearchX } from 'lucide-react';
import { Fragment, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router';
import { useStigBenchmarkRules, useStigBenchmarks } from '@/api/queries';
import type { StigBenchmarkRule } from '@/api/types';
import { EmptyState, ErrorAlert, PageHeader } from '@/components/page';
import { PRODUCT_STIGS_HREF } from '@/components/product-stigs';
import { SimpleSelect } from '@/components/simple-select';
import { CatBadge, CatOpenChips, ResultBadge, SourceBadge, StigResultBar } from '@/components/stig';
import { Pager, SearchInput, SkeletonRows, StateRow, Toolbar, useClientPagination } from '@/components/table-kit';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { CAT_LABEL, normResult, passRate } from '@/lib/stig';
import { cn } from '@/lib/utils';

const CAT_FILTER = (['cat1', 'cat2', 'cat3'] as const).map((c) => ({ value: c, label: CAT_LABEL[c] }));
const COLS = 6;

function ImageList({ rule }: { rule: StigBenchmarkRule }) {
  // failing first, then passing, then everything else
  const order = (r?: string) => ({ fail: 0, error: 1, pass: 2 })[normResult(r) as 'fail' | 'error' | 'pass'] ?? 3;
  const list = [...rule.images].sort((a, b) => order(a.result) - order(b.result) || a.ref.localeCompare(b.ref));
  if (!list.length) return <p className="text-muted-foreground text-sm">{rule.failingImages ? 'The API did not list the images behind these counts.' : 'No image fails this rule.'}</p>;
  const listed = list.filter((i) => normResult(i.result) === 'fail').length;
  return (
    <>
    {rule.failingImages > listed ? <p className="mb-1 text-muted-foreground text-xs">Showing {listed} of {rule.failingImages} failing images.</p> : null}
    <ul className="flex flex-col gap-1.5" aria-label={`Images evaluated for ${rule.stigId ?? rule.ruleId}`}>
      {list.map((i) => (
        <li key={i.imageId} className="flex items-center gap-2">
          {i.result ? <ResultBadge result={i.result} /> : null}
          <Link to={`/images/${encodeURIComponent(i.imageId)}?tab=stig`} className="truncate font-mono text-xs underline-offset-4 hover:underline" title={i.ref}>
            {i.ref}
          </Link>
        </li>
      ))}
    </ul>
    </>
  );
}

/** `/stig/benchmarks/:id` (§14): rules of one benchmark rolled up across images. */
export function StigBenchmarkPage() {
  const { id = '' } = useParams();
  const catalogue = useStigBenchmarks();
  const rules = useStigBenchmarkRules(id);
  const bench = catalogue.data?.find((b) => b.id === id) ?? rules.data?.benchmark ?? undefined;
  const [q, setQ] = useState('');
  const [cat, setCat] = useState('');
  const [failingOnly, setFailingOnly] = useState(true);
  const [open, setOpen] = useState<Set<string>>(() => new Set());

  const all = useMemo(() => rules.data?.rules ?? [], [rules.data]);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return all
      .filter((r) => (!failingOnly || r.failingImages > 0) && (!cat || r.cat === cat) && (!needle || [r.title ?? '', r.ruleId, r.stigId ?? '', ...(r.cci ?? [])].some((x) => x.toLowerCase().includes(needle))))
      .sort((a, b) => b.failingImages - a.failingImages || a.cat.localeCompare(b.cat) || a.ruleId.localeCompare(b.ruleId));
  }, [all, q, cat, failingOnly]);
  const { pageRows, pagerProps } = useClientPagination(filtered, { resetKey: `${id}|${q}|${cat}|${failingOnly}` });
  const failingRules = all.filter((r) => r.failingImages > 0).length;
  const openBy = (c: string) => all.filter((r) => r.cat === c).reduce((a, r) => a + r.failingImages, 0);
  const toggle = (key: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  const title = bench?.title ?? id;
  const p = bench ? passRate(bench.pass, bench.fail) : null;

  return (
    <>
      <PageHeader
        title={title}
        description="Failing rules of this benchmark across every evaluated image. Expand a rule to see which images fail or pass it."
        crumbs={[{ label: 'Compliance', to: '/compliance' }, { label: 'Product STIGs', to: PRODUCT_STIGS_HREF }, { label: title }]}
      />
      {catalogue.error ? <ErrorAlert error={catalogue.error} onRetry={() => void catalogue.refetch()} title="Couldn’t load the benchmark catalogue" /> : null}
      <Card>
        <CardContent className="flex flex-col gap-4 md:flex-row md:items-center">
          <div className="flex min-w-0 flex-1 flex-col gap-2">
            <div className="flex flex-wrap items-center gap-2">
              {bench?.version ? <Badge variant="outline" className="font-mono">{bench.version}</Badge> : null}
              {bench ? <SourceBadge source={bench.source} /> : null}
              {bench?.profileId ? <code className="break-all text-muted-foreground text-xs">{bench.profileId}</code> : null}
            </div>
            {bench ? <StigResultBar counts={bench} /> : null}
          </div>
          <dl className="grid shrink-0 grid-cols-3 gap-6 text-sm">
            <div>
              <dt className="text-muted-foreground text-xs">Images evaluated</dt>
              <dd className="font-semibold text-2xl tabular-nums">{bench?.imagesEvaluated ?? '—'}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground text-xs">Pass rate</dt>
              <dd className="font-semibold text-2xl tabular-nums">{p === null ? '—' : `${p.toFixed(0)}%`}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground text-xs">Failing rules</dt>
              <dd className="font-semibold text-2xl tabular-nums">{rules.isLoading ? '…' : failingRules}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Rules across images</CardTitle>
          <CardDescription className="flex flex-wrap items-center gap-2">
            Open (image, rule) pairs
            <CatOpenChips cat1={bench?.cat1Open ?? (rules.data ? openBy('cat1') : undefined)} cat2={bench?.cat2Open ?? (rules.data ? openBy('cat2') : undefined)} cat3={bench?.cat3Open ?? (rules.data ? openBy('cat3') : undefined)} />
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Toolbar>
            <SearchInput label="Search benchmark rules" placeholder="Search title, V-ID, CCI…" value={q} onChange={setQ} />
            <SimpleSelect ariaLabel="Category" allLabel="All categories" value={cat} onChange={setCat} options={CAT_FILTER} />
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={failingOnly} onCheckedChange={setFailingOnly} aria-label="Only failing rules" />
              Failing only
            </label>
          </Toolbar>
          {rules.error ? <ErrorAlert error={rules.error} onRetry={() => void rules.refetch()} /> : null}
          <Table aria-label="Benchmark rules" aria-busy={rules.isLoading || undefined}>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-8 px-2" aria-label="Images" />
                <TableHead className="px-3">Rule</TableHead>
                <TableHead className="px-3">V-ID</TableHead>
                <TableHead className="px-3">CAT</TableHead>
                <TableHead className="px-3 text-right">Failing images</TableHead>
                <TableHead className="px-3 text-right">Passing images</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.isLoading ? (
                <SkeletonRows cols={COLS} />
              ) : pageRows.length === 0 ? (
                <StateRow cols={COLS}>
                  <EmptyState icon={<SearchX className="size-6" />} title={all.length ? (failingOnly && !q && !cat ? 'No failing rules' : 'No rules match') : 'No rules'}>
                    {all.length ? (failingOnly && !q && !cat ? 'Every evaluated image passes every rule of this benchmark.' : 'Clear the filters to see all rules.') : 'No image has been evaluated against this benchmark.'}
                  </EmptyState>
                </StateRow>
              ) : (
                pageRows.map((r) => {
                  const expanded = open.has(r.ruleId);
                  return (
                    <Fragment key={r.ruleId}>
                      <TableRow>
                        <TableCell className="px-2 py-2">
                          <Button size="icon-xs" variant="ghost" aria-expanded={expanded} aria-label={`${expanded ? 'Hide' : 'Show'} images for ${r.stigId ?? r.ruleId}`} onClick={() => toggle(r.ruleId)}>
                            {expanded ? <ChevronDown /> : <ChevronRight />}
                          </Button>
                        </TableCell>
                        <TableCell className="max-w-[560px] whitespace-normal px-3 py-2">
                          <span className="block">{r.title ?? r.ruleId}</span>
                          <code className="block truncate text-[11px] text-muted-foreground" title={r.ruleId}>
                            {r.ruleId}
                          </code>
                        </TableCell>
                        <TableCell className="whitespace-nowrap px-3 py-2 font-mono text-xs">{r.stigId ?? <span className="text-muted-foreground">—</span>}</TableCell>
                        <TableCell className="px-3 py-2">
                          <CatBadge cat={r.cat} />
                        </TableCell>
                        <TableCell className={cn('px-3 py-2 text-right tabular-nums', r.failingImages ? 'font-semibold text-destructive-foreground' : 'text-muted-foreground')}>{r.failingImages}</TableCell>
                        <TableCell className="px-3 py-2 text-right text-muted-foreground tabular-nums">{r.passingImages}</TableCell>
                      </TableRow>
                      {expanded ? (
                        <TableRow className="hover:bg-transparent">
                          <TableCell colSpan={COLS} className="bg-muted/40 px-10 py-3">
                            <ImageList rule={r} />
                            {r.fixText ? (
                              <p className="mt-3 whitespace-pre-wrap text-sm">
                                <span className="mr-1 text-[11px] text-muted-foreground uppercase tracking-wide">Fix</span>
                                {r.fixText}
                              </p>
                            ) : null}
                          </TableCell>
                        </TableRow>
                      ) : null}
                    </Fragment>
                  );
                })
              )}
            </TableBody>
          </Table>
          {filtered.length > pagerProps.pageSizeOptions[0] ? <Pager {...pagerProps} /> : null}
        </CardContent>
      </Card>
    </>
  );
}
