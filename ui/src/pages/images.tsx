import { Boxes, SearchX } from 'lucide-react';
import { Link } from 'react-router';
import { useImages, useNamespaces } from '@/api/queries';
import type { ImageQuery } from '@/api/types';
import { EmptyState, ErrorAlert, PageHeader } from '@/components/page';
import { AgreementDots, GradeBadge, ScannerGlyphs, SeverityChips } from '@/components/posture';
import { SimpleSelect } from '@/components/simple-select';
import { ProvenanceGlyph, SbomGlyph, SignatureGlyph, UpdateIndicator } from '@/components/supply-chain';
import { Pager, SearchInput, SkeletonRows, SortableHead, StateRow, Toolbar, useUrlState } from '@/components/table-kit';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { formatRelative, shortDigest } from '@/lib/format';

const GRADE_OPTIONS = ['A', 'B', 'C', 'D', 'F', '?'].map((g) => ({ value: g, label: g === '?' ? 'Not scored (?)' : `Grade ${g}` }));
const SEVERITY_OPTIONS = [
  { value: 'critical', label: 'Has critical' },
  { value: 'high', label: 'High or worse' },
  { value: 'medium', label: 'Medium or worse' },
  { value: 'low', label: 'Low or worse' },
];
const COLS = 12;

export function ImagesPage() {
  const [state, update] = useUrlState({ namespace: '', grade: '', severity: '', q: '', sort: 'score', order: 'asc', page: '1', pageSize: '50' });
  const query: ImageQuery = {
    namespace: state.namespace || undefined,
    grade: state.grade || undefined,
    severity: state.severity || undefined,
    q: state.q || undefined,
    sort: state.sort,
    order: state.order === 'desc' ? 'desc' : 'asc',
    page: Number(state.page) || 1,
    pageSize: Number(state.pageSize) || 50,
  };
  const { data, error, isLoading, isFetching, refetch } = useImages(query);
  const namespaces = useNamespaces();
  const filtered = Boolean(state.namespace || state.grade || state.severity || state.q);
  const onSort = (sort: string, order: 'asc' | 'desc') => update({ sort, order });

  return (
    <>
      <PageHeader title="Images" description="Every unique image digest running in the cluster, scored by three-scanner consensus." />
      <Card>
        <CardContent className="flex flex-col gap-4">
          <Toolbar>
            <SearchInput label="Search images" placeholder="Search ref or digest…" value={state.q} onChange={(q) => update({ q })} />
            <SimpleSelect
              ariaLabel="Namespace"
              allLabel="All namespaces"
              className="w-48"
              value={state.namespace}
              onChange={(namespace) => update({ namespace })}
              options={(namespaces.data ?? []).map((n) => ({ value: n.name, label: n.name }))}
            />
            <SimpleSelect ariaLabel="Grade" allLabel="Any grade" value={state.grade} onChange={(grade) => update({ grade })} options={GRADE_OPTIONS} />
            <SimpleSelect ariaLabel="Severity" allLabel="Any severity" value={state.severity} onChange={(severity) => update({ severity })} options={SEVERITY_OPTIONS} />
            {filtered ? (
              <Button variant="ghost" size="sm" onClick={() => update({ namespace: '', grade: '', severity: '', q: '' })}>
                Clear filters
              </Button>
            ) : null}
            {isFetching && !isLoading ? <span className="ml-auto text-muted-foreground text-xs">Updating…</span> : null}
          </Toolbar>

          {error ? <ErrorAlert error={error} onRetry={() => void refetch()} /> : null}

          <Table aria-label="Images" aria-busy={isLoading || undefined}>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <SortableHead label="Image" field="ref" sort={state.sort} order={state.order} onSort={onSort} />
                <SortableHead label="Grade" field="score" sort={state.sort} order={state.order} onSort={onSort} />
                <SortableHead label="Findings" field="critical" sort={state.sort} order={state.order} onSort={onSort} />
                <TableHead className="px-3">Scanners</TableHead>
                <SortableHead label="Agreement" field="agreement" sort={state.sort} order={state.order} onSort={onSort} />
                <TableHead className="px-2 text-center" title="Signature (cosign)">Signed</TableHead>
                <TableHead className="px-2 text-center" title="SBOM attestation">SBOM</TableHead>
                <TableHead className="px-2 text-center" title="SLSA provenance attestation">Provenance</TableHead>
                <TableHead className="px-3">Update</TableHead>
                <TableHead className="px-3">Namespaces</TableHead>
                <SortableHead label="Workloads" field="workloads" sort={state.sort} order={state.order} onSort={onSort} />
                <SortableHead label="Last scanned" field="lastScannedAt" sort={state.sort} order={state.order} onSort={onSort} />
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <SkeletonRows cols={COLS} />
              ) : data && data.items.length === 0 ? (
                <StateRow cols={COLS}>
                  {filtered ? (
                    <EmptyState icon={<SearchX className="size-6" />} title="No images match these filters">
                      Try a different search or clear your filters.
                    </EmptyState>
                  ) : (
                    <EmptyState icon={<Boxes className="size-6" />} title="No images yet">
                      Images appear after the first inventory scan completes.
                    </EmptyState>
                  )}
                </StateRow>
              ) : (
                data?.items.map((image) => (
                  <TableRow key={image.id}>
                    <TableCell className="max-w-[260px] px-3 py-2">
                      <Link to={`/images/${encodeURIComponent(image.id)}`} className="block truncate font-mono text-xs underline-offset-4 hover:underline" title={image.ref}>
                        {image.ref}
                      </Link>
                      <span className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                        <span className="font-mono">{shortDigest(image.digest)}</span>
                        {!image.running ? <Badge variant="outline" className="h-4 px-1 text-[10px]">not running</Badge> : null}
                        {image.warnings.length ? <span className="text-warning-foreground" title={image.warnings.join('\n')}>⚠ {image.warnings.length}</span> : null}
                      </span>
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <GradeBadge grade={image.grade} score={image.score} />
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <SeverityChips counts={image.counts} />
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <ScannerGlyphs scanners={image.scanners} />
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <AgreementDots value={image.agreementIndex} />
                    </TableCell>
                    <TableCell className="px-2 py-2 text-center">
                      <SignatureGlyph provenance={image.provenance} />
                    </TableCell>
                    <TableCell className="px-2 py-2 text-center">
                      <SbomGlyph provenance={image.provenance} />
                    </TableCell>
                    <TableCell className="px-2 py-2 text-center">
                      <ProvenanceGlyph provenance={image.provenance} />
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <UpdateIndicator update={image.provenance?.update} className="max-w-28" />
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <span className="flex flex-wrap gap-1">
                        {image.namespaces.slice(0, 2).map((ns) => (
                          <Badge key={ns} variant="outline" render={<button type="button" onClick={() => update({ namespace: ns })} />} className="cursor-pointer">
                            {ns}
                          </Badge>
                        ))}
                        {image.namespaces.length > 2 ? <Badge variant="ghost" title={image.namespaces.slice(2).join(', ')}>+{image.namespaces.length - 2}</Badge> : null}
                      </span>
                    </TableCell>
                    <TableCell className="px-3 py-2 text-right tabular-nums">{image.workloads}</TableCell>
                    <TableCell className="whitespace-nowrap px-3 py-2 text-muted-foreground text-xs">{formatRelative(image.lastScannedAt)}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>

          {data && data.total > 0 ? (
            <Pager
              page={query.page ?? 1}
              pageSize={query.pageSize ?? 50}
              total={data.total}
              onPage={(page) => update({ page: String(page) }, false)}
              onPageSize={(pageSize) => update({ pageSize: String(pageSize) })}
            />
          ) : null}
        </CardContent>
      </Card>
    </>
  );
}
