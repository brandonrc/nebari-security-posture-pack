import { ExternalLink, SearchX } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import type { Finding, ScannerName, ScannerRunSummary, Severity } from '@/api/types';
import { SCANNERS } from '@/api/types';
import { EmptyState } from '@/components/page';
import { ControlChips, SCANNER_LABEL, SeverityBadge } from '@/components/posture';
import { SimpleSelect } from '@/components/simple-select';
import { SearchInput, SortableHead, StateRow, Toolbar } from '@/components/table-kit';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { compareSeverity } from '@/lib/scoring';
import { cn } from '@/lib/utils';

const SEV_FILTER = (['critical', 'high', 'medium', 'low', 'negligible', 'unknown'] as Severity[]).map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) }));

/**
 * The three-scanner consensus view: one row per (CVE, package) with each
 * scanner's own severity side by side. Rows all three scanners agree on are
 * highlighted.
 */
export function FindingsTable({ findings, scanners }: { findings: Finding[]; scanners: Partial<Record<ScannerName, ScannerRunSummary>> }) {
  const [q, setQ] = useState('');
  const [severity, setSeverity] = useState('');
  const [onlyFixable, setOnlyFixable] = useState(false);
  const [onlyDisagree, setOnlyDisagree] = useState(false);
  const [sort, setSort] = useState('severity');
  const [order, setOrder] = useState<'asc' | 'desc'>('desc');
  const okScanners = SCANNERS.filter((s) => scanners[s]?.status === 'ok');

  const rows = useMemo(() => {
    const needle = q.toLowerCase();
    const list = findings.filter(
      (f) =>
        (!needle || f.vulnId.toLowerCase().includes(needle) || f.package.toLowerCase().includes(needle) || (f.title ?? '').toLowerCase().includes(needle)) &&
        (!severity || f.severity === severity) &&
        (!onlyFixable || f.fixable) &&
        (!onlyDisagree || f.scanners.length < okScanners.length),
    );
    const dir = order === 'asc' ? 1 : -1;
    return list.sort((a, b) => {
      let cmp = 0;
      if (sort === 'severity') cmp = -compareSeverity(a.severity, b.severity) || (a.cvss ?? 0) - (b.cvss ?? 0);
      else if (sort === 'vulnId') cmp = a.vulnId.localeCompare(b.vulnId);
      else if (sort === 'package') cmp = a.package.localeCompare(b.package);
      else if (sort === 'agreement') cmp = a.scanners.length - b.scanners.length;
      return cmp * dir;
    });
  }, [findings, q, severity, onlyFixable, onlyDisagree, sort, order, okScanners.length]);

  const onSort = (field: string, next: 'asc' | 'desc') => {
    setSort(field);
    setOrder(next);
  };
  const agreedAll = findings.filter((f) => okScanners.length > 1 && f.scanners.length === okScanners.length).length;
  const COLS = 9;

  return (
    <div className="flex flex-col gap-3">
      <Toolbar>
        <SearchInput label="Search findings" placeholder="Search CVE, package…" value={q} onChange={setQ} />
        <SimpleSelect ariaLabel="Severity" allLabel="All severities" value={severity} onChange={setSeverity} options={SEV_FILTER} />
        <label className="flex items-center gap-2 text-sm">
          <Switch checked={onlyFixable} onCheckedChange={setOnlyFixable} aria-label="Only fixable" />
          Fixable only
        </label>
        <label className="flex items-center gap-2 text-sm">
          <Switch checked={onlyDisagree} onCheckedChange={setOnlyDisagree} aria-label="Only disagreements" />
          Disagreements only
        </label>
        <span className="ml-auto text-muted-foreground text-xs">
          <span className="mr-1 inline-block size-2.5 rounded-sm border border-primary/40 bg-primary/10 align-middle" aria-hidden="true" />
          {agreedAll} of {findings.length} flagged by all {okScanners.length} scanners
        </span>
      </Toolbar>
      <Table aria-label="Findings">
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <SortableHead label="Vulnerability" field="vulnId" sort={sort} order={order} onSort={onSort} />
            <SortableHead label="Consensus" field="severity" sort={sort} order={order} onSort={onSort} />
            <SortableHead label="Package" field="package" sort={sort} order={order} onSort={onSort} />
            <TableHead className="px-3">Installed → Fixed</TableHead>
            {SCANNERS.map((s) => (
              <TableHead key={s} className="px-3 text-center">
                {SCANNER_LABEL[s]}
              </TableHead>
            ))}
            <SortableHead label="Agree" field="agreement" sort={sort} order={order} onSort={onSort} />
            <TableHead className="px-3">Controls</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.length === 0 ? (
            <StateRow cols={COLS}>
              <EmptyState icon={<SearchX className="size-6" />} title={findings.length ? 'No findings match' : 'No vulnerabilities found'}>
                {findings.length ? 'Clear the filters to see all findings.' : 'All scanners that ran reported a clean image.'}
              </EmptyState>
            </StateRow>
          ) : (
            rows.map((f) => {
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
    </div>
  );
}
