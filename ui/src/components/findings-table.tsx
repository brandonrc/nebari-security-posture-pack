import { ExternalLink, SearchX, TriangleAlert } from 'lucide-react';
import { Link } from 'react-router';
import type { FindingSort, ImageDetail, ImageFindingsQuery, Severity } from '@/api/types';
import { SCANNERS } from '@/api/types';
import { EmptyState } from '@/components/page';
import { ControlChips, SCANNER_LABEL, SeverityBadge } from '@/components/posture';
import { SimpleSelect } from '@/components/simple-select';
import { Pager, SearchInput, SkeletonRows, SortableHead, StateRow, Toolbar } from '@/components/table-kit';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';

const SEV_FILTER = (['critical', 'high', 'medium', 'low', 'negligible', 'unknown'] as Severity[]).map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) }));

export const FINDINGS_PAGE_SIZES = [25, 50, 100, 250];

/** Table state = the `GET /images/{id}` findings query (all fields resolved). */
export type FindingsQuery = Required<Pick<ImageFindingsQuery, 'page' | 'pageSize' | 'sort' | 'order'>> & Omit<ImageFindingsQuery, 'page' | 'pageSize' | 'sort' | 'order'>;

export const DEFAULT_FINDINGS_QUERY: FindingsQuery = { page: 1, pageSize: 50, sort: 'severity', order: 'desc' };

/**
 * The three-scanner consensus view: one row per (CVE, package) with each
 * scanner's own severity side by side. Rows all three scanners agree on are
 * highlighted.
 *
 * Server-paged: `image.findings` is one page, filtered and sorted by the API
 * from `query`; totals and the agreement line come from `findingsSummary`
 * (the whole filtered set). `onQueryChange` patches the query; any change
 * other than `page` itself goes back to page 1.
 */
export function FindingsTable({
  image,
  query,
  onQueryChange,
  loading = false,
}: {
  image: Pick<ImageDetail, 'findings' | 'findingsTotal' | 'findingsSummary' | 'truncated' | 'scanners'>;
  query: FindingsQuery;
  onQueryChange: (patch: Partial<FindingsQuery>) => void;
  /** a new page/filter is loading; the previous page is still in `image` */
  loading?: boolean;
}) {
  const { findings, scanners, findingsSummary: summary } = image;
  const okScanners = SCANNERS.filter((s) => scanners[s]?.status === 'ok');
  const total = summary?.filtered ?? image.findingsTotal ?? findings.length;
  const imageTotal = summary?.total ?? total;
  // older APIs without findingsSummary: best effort over the returned rows
  const agreedAll = summary?.flaggedByAll ?? findings.filter((f) => okScanners.length > 1 && f.scanners.length === okScanners.length).length;
  const filtered = Boolean(query.q || query.severity || query.fixable || query.disagree);

  const onSort = (field: string, next: 'asc' | 'desc') => onQueryChange({ sort: field as FindingSort, order: next });
  const COLS = 9;

  return (
    <div className="flex flex-col gap-3">
      {image.truncated ? (
        <Alert variant="warning">
          <TriangleAlert />
          <AlertTitle>Findings list truncated</AlertTitle>
          <AlertDescription>
            The API returned only the first {findings.length.toLocaleString()} of {total.toLocaleString()} findings. Narrow the filters or page through the
            results to see the rest.
          </AlertDescription>
        </Alert>
      ) : null}
      <Toolbar>
        <SearchInput label="Search findings" placeholder="Search CVE, package…" value={query.q ?? ''} onChange={(v) => onQueryChange({ q: v || undefined })} />
        <SimpleSelect ariaLabel="Severity" allLabel="All severities" value={query.severity ?? ''} onChange={(v) => onQueryChange({ severity: v || undefined })} options={SEV_FILTER} />
        <label className="flex items-center gap-2 text-sm">
          <Switch checked={Boolean(query.fixable)} onCheckedChange={(v) => onQueryChange({ fixable: v || undefined })} aria-label="Only fixable" />
          Fixable only
        </label>
        <label className="flex items-center gap-2 text-sm">
          <Switch checked={Boolean(query.disagree)} onCheckedChange={(v) => onQueryChange({ disagree: v || undefined })} aria-label="Only disagreements" />
          Disagreements only
        </label>
        <span className="ml-auto text-muted-foreground text-xs">
          <span className="mr-1 inline-block size-2.5 rounded-sm border border-primary/40 bg-primary/10 align-middle" aria-hidden="true" />
          {agreedAll.toLocaleString()} of {total.toLocaleString()} flagged by all {okScanners.length} scanners
        </span>
      </Toolbar>
      <Table aria-label="Findings" aria-busy={loading || undefined}>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <SortableHead label="Vulnerability" field="vulnId" sort={query.sort} order={query.order} onSort={onSort} />
            <SortableHead label="Consensus" field="severity" sort={query.sort} order={query.order} onSort={onSort} />
            <SortableHead label="Package" field="package" sort={query.sort} order={query.order} onSort={onSort} />
            <TableHead className="px-3">Installed → Fixed</TableHead>
            {SCANNERS.map((s) => (
              <TableHead key={s} className="px-3 text-center">
                {SCANNER_LABEL[s]}
              </TableHead>
            ))}
            <SortableHead label="Agree" field="agreement" sort={query.sort} order={query.order} onSort={onSort} />
            <TableHead className="px-3">Controls</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading ? (
            <SkeletonRows cols={COLS} rows={Math.min(query.pageSize, 10)} />
          ) : findings.length === 0 ? (
            <StateRow cols={COLS}>
              <EmptyState icon={<SearchX className="size-6" />} title={imageTotal || filtered ? 'No findings match' : 'No vulnerabilities found'}>
                {imageTotal || filtered ? 'Clear the filters to see all findings.' : 'All scanners that ran reported a clean image.'}
              </EmptyState>
            </StateRow>
          ) : (
            findings.map((f) => {
              const allAgree = okScanners.length > 1 && f.scanners.length === okScanners.length;
              return (
                <TableRow
                  key={`${f.vulnId}:${f.package}`}
                  data-agree={allAgree || undefined}
                  className={cn(allAgree && 'bg-primary/[0.06] shadow-[inset_3px_0_0_var(--primary)] hover:bg-primary/10')}
                >
                  <TableCell className="max-w-[240px] px-3 py-2">
                    <span className="flex items-center gap-1">
                      <Link to={`/vulnerabilities/${encodeURIComponent(f.vulnId)}`} className="font-mono text-xs underline-offset-4 hover:underline">
                        {f.vulnId}
                      </Link>
                      {f.url ? (
                        <a href={f.url} target="_blank" rel="noreferrer" aria-label={`${f.vulnId} advisory`} className="text-muted-foreground hover:text-foreground">
                          <ExternalLink className="size-3" />
                        </a>
                      ) : null}
                      {f.overdue ? <Badge variant="destructive" className="h-4 px-1 text-[10px]">past SLA</Badge> : null}
                    </span>
                    {f.title ? <span className="block truncate text-muted-foreground text-xs" title={f.title}>{f.title}</span> : null}
                  </TableCell>
                  <TableCell className="whitespace-nowrap px-3 py-2">
                    <SeverityBadge severity={f.severity} />
                    {f.cvss !== null ? <span className="ml-1.5 text-muted-foreground text-xs tabular-nums">{f.cvss.toFixed(1)}</span> : null}
                  </TableCell>
                  <TableCell className="px-3 py-2">
                    <span className="font-mono text-xs">{f.package}</span>
                    <span className="block text-[11px] text-muted-foreground">{f.pkgType}</span>
                  </TableCell>
                  <TableCell className="px-3 py-2 font-mono text-xs">
                    <span>{f.installedVersion}</span>
                    <span className="text-muted-foreground"> → </span>
                    {f.fixedVersion ? <span className="text-success-foreground">{f.fixedVersion}</span> : <span className="text-muted-foreground">no fix</span>}
                  </TableCell>
                  {SCANNERS.map((s) => {
                    const sev = f.perScanner[s];
                    const ran = scanners[s]?.status === 'ok';
                    return (
                      <TableCell key={s} className="px-3 py-2 text-center">
                        {sev ? (
                          <SeverityBadge severity={sev} className="text-[10px]" />
                        ) : (
                          <span className="text-muted-foreground" title={ran ? `${SCANNER_LABEL[s]} did not report this` : `${SCANNER_LABEL[s]} did not complete`}>
                            {ran ? '–' : 'n/a'}
                          </span>
                        )}
                      </TableCell>
                    );
                  })}
                  <TableCell className="px-3 py-2 text-xs tabular-nums">
                    {f.scanners.length}/{okScanners.length || 3}
                  </TableCell>
                  <TableCell className="px-3 py-2">
                    <ControlChips controls={f.controls} max={2} />
                  </TableCell>
                </TableRow>
              );
            })
          )}
        </TableBody>
      </Table>
      {total > 0 ? (
        <Pager
          page={query.page}
          pageSize={query.pageSize}
          total={total}
          onPage={(page) => onQueryChange({ page })}
          onPageSize={(pageSize) => onQueryChange({ pageSize })}
          pageSizeOptions={FINDINGS_PAGE_SIZES}
        />
      ) : null}
    </div>
  );
}
