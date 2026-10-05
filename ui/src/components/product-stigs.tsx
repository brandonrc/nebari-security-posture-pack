import { ArrowRight, Layers } from 'lucide-react';
import { useEffect, useRef } from 'react';
import { Link, useLocation } from 'react-router';
import { useStigBenchmarks } from '@/api/queries';
import type { StigBenchmark } from '@/api/types';
import { CardsSkeleton, EmptyState, ErrorAlert } from '@/components/page';
import { CatOpenChips, SourceBadge, StigResultBar } from '@/components/stig';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { passRate } from '@/lib/stig';

export const PRODUCT_STIGS_ANCHOR = 'product-stigs';
export const PRODUCT_STIGS_HREF = `/compliance?tab=stig#${PRODUCT_STIGS_ANCHOR}`;

export function benchmarkHref(id: string) {
  return `/stig/benchmarks/${encodeURIComponent(id)}`;
}

function PassPct({ b }: { b: StigBenchmark }) {
  const p = passRate(b.pass, b.fail);
  return (
    <span className="flex min-w-36 flex-col gap-1">
      <span className="text-xs tabular-nums">{p === null ? '—' : `${p.toFixed(0)}%`}</span>
      <StigResultBar counts={b} legend={false} />
    </span>
  );
}

/**
 * Compliance → STIG → "Product STIGs" (§14): one row per benchmark from `/compliance/stig`
 * `product` (or `GET /stig/benchmarks` when the API has no `product` section).
 */
export function ProductStigs({ product, loading }: { product: StigBenchmark[] | null | undefined; loading: boolean }) {
  // fall back to the catalogue only once /compliance/stig answered without `product`
  const fallback = useStigBenchmarks(!loading && product === null);
  // catalogue entries with `id: null` are content that applies to no image: not a rollup row
  const rows = (product ?? fallback.data ?? []).filter((b) => b.id);
  const busy = loading || (product === null && fallback.isLoading);
  const { hash } = useLocation();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (hash === `#${PRODUCT_STIGS_ANCHOR}` && !busy) ref.current?.scrollIntoView?.({ block: 'start' });
  }, [hash, busy]);

  return (
    <Card id={PRODUCT_STIGS_ANCHOR} ref={ref} className="scroll-mt-4">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Layers className="size-4" /> Product STIGs
        </CardTitle>
        <CardDescription>
          Operating-system and product STIGs evaluated inside each image with OpenSCAP (DISA SCAP benchmarks, ComplianceAsCode content). Open counts are failing
          (image, rule) pairs.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {busy ? (
          <CardsSkeleton count={1} className="sm:grid-cols-1 xl:grid-cols-1" />
        ) : product === null && fallback.error ? (
          <ErrorAlert error={fallback.error} onRetry={() => void fallback.refetch()} title="Couldn’t load product STIG benchmarks" />
        ) : rows.length === 0 ? (
          <EmptyState icon={<Layers className="size-6" />} title="No product STIG results">
            No image has been evaluated against a SCAP benchmark yet. Enable the SCAP scanner in Settings → SCAP; images without applicable content are reported as
            not applicable.
          </EmptyState>
        ) : (
          <Table aria-label="Product STIG benchmarks">
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="px-3">Benchmark</TableHead>
                <TableHead className="px-3">Version</TableHead>
                <TableHead className="px-3">Source</TableHead>
                <TableHead className="px-3 text-right">Images evaluated</TableHead>
                <TableHead className="px-3">Pass</TableHead>
                <TableHead className="px-3">Open</TableHead>
                <TableHead className="px-3" aria-label="Details" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((b) => (
                <TableRow key={b.id}>
                  <TableCell className="max-w-[360px] whitespace-normal px-3 py-2">
                    <Link to={benchmarkHref(b.id)} className="font-medium underline-offset-4 hover:underline">
                      {b.title}
                    </Link>
                    {b.profileId ? <code className="block truncate text-[11px] text-muted-foreground" title={b.profileId}>{b.profileId}</code> : null}
                  </TableCell>
                  <TableCell className="px-3 py-2 font-mono text-xs">{b.version || '—'}</TableCell>
                  <TableCell className="px-3 py-2">
                    <SourceBadge source={b.source} />
                  </TableCell>
                  <TableCell className="px-3 py-2 text-right tabular-nums">{b.imagesEvaluated}</TableCell>
                  <TableCell className="px-3 py-2">
                    <PassPct b={b} />
                  </TableCell>
                  <TableCell className="px-3 py-2">
                    <CatOpenChips cat1={b.cat1Open} cat2={b.cat2Open} cat3={b.cat3Open} />
                  </TableCell>
                  <TableCell className="px-3 py-2 text-right">
                    <Link to={benchmarkHref(b.id)} aria-label={`Failing rules for ${b.title}`} className="inline-flex items-center gap-1 text-muted-foreground text-xs hover:text-foreground">
                      Failing rules <ArrowRight className="size-3.5" />
                    </Link>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
