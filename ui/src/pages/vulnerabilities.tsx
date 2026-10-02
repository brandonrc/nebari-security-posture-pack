import { Bug, ExternalLink, SearchX } from 'lucide-react';
import { Link } from 'react-router';
import { useVulns } from '@/api/queries';
import type { ScannerName, Severity } from '@/api/types';
import { SCANNERS } from '@/api/types';
import { EmptyState, ErrorAlert, PageHeader } from '@/components/page';
import { ControlChips, SCANNER_LABEL, SeverityBadge } from '@/components/posture';
import { SimpleSelect } from '@/components/simple-select';
import { Pager, SearchInput, SkeletonRows, StateRow, Toolbar, useUrlState } from '@/components/table-kit';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'];
const COLS = 9;

export function ScannerPresence({ scanners }: { scanners: ScannerName[] }) {
  return (
    <span className="inline-flex gap-1">
      {SCANNERS.map((s) => {
        const on = scanners.includes(s);
        return (
          <span
            key={s}
            title={`${SCANNER_LABEL[s]}: ${on ? 'reported' : 'not reported'}`}
            className={cn(
              'inline-flex h-5 w-6 items-center justify-center rounded-sm border font-mono text-[10px]',
              on ? 'border-primary/40 bg-primary/10 text-foreground' : 'border-border border-dashed text-muted-foreground/60',
            )}
          >
            {SCANNER_LABEL[s][0]}
          </span>
        );
      })}
    </span>
  );
}

export function VulnerabilitiesPage() {
  const [state, update] = useUrlState({ severity: '', q: '', fixable: '', page: '1', pageSize: '50' });
  const page = Number(state.page) || 1;
  const pageSize = Number(state.pageSize) || 50;
  const { data, error, isLoading, refetch } = useVulns({
    severity: state.severity || undefined,
    q: state.q || undefined,
    fixable: state.fixable === 'true' ? true : undefined,
    page,
    pageSize,
  });
  const filtered = Boolean(state.severity || state.q || state.fixable);

  return (
    <>
      <PageHeader title="Vulnerabilities" description="CVE-centric view: each vulnerability once, with how many images and workloads it reaches." />
      <Card>
        <CardContent className="flex flex-col gap-4">
          <Toolbar>
            <SearchInput label="Search vulnerabilities" placeholder="Search CVE or title…" value={state.q} onChange={(q) => update({ q })} />
            <SimpleSelect
              ariaLabel="Severity"
              allLabel="All severities"
              value={state.severity}
              onChange={(severity) => update({ severity })}
              options={SEVERITIES.map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) }))}
            />
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={state.fixable === 'true'} onCheckedChange={(v) => update({ fixable: v ? 'true' : '' })} aria-label="Fix available only" />
              Fix available
            </label>
          </Toolbar>
          {error ? <ErrorAlert error={error} onRetry={() => void refetch()} /> : null}
          <Table aria-label="Vulnerabilities">
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="px-3">Vulnerability</TableHead>
                <TableHead className="px-3">Severity</TableHead>
                <TableHead className="px-3 text-right">CVSS</TableHead>
                <TableHead className="px-3">Scanners</TableHead>
                <TableHead className="px-3 text-right">Images</TableHead>
                <TableHead className="px-3 text-right">Workloads</TableHead>
                <TableHead className="px-3">Fix</TableHead>
                <TableHead className="px-3">Controls</TableHead>
                <TableHead className="px-3">Advisory</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <SkeletonRows cols={COLS} />
              ) : data && data.items.length === 0 ? (
                <StateRow cols={COLS}>
                  {filtered ? (
                    <EmptyState icon={<SearchX className="size-6" />} title="No vulnerabilities match">Try a different search or clear your filters.</EmptyState>
                  ) : (
                    <EmptyState icon={<Bug className="size-6" />} title="No vulnerabilities">No scanner reported a vulnerability in running images.</EmptyState>
                  )}
                </StateRow>
              ) : (
                data?.items.map((v) => (
                  <TableRow key={v.vulnId}>
                    <TableCell className="max-w-[380px] px-3 py-2">
                      <Link to={`/vulnerabilities/${encodeURIComponent(v.vulnId)}`} className="font-mono text-xs underline-offset-4 hover:underline">
                        {v.vulnId}
                      </Link>
                      {v.title ? <span className="block truncate text-muted-foreground text-xs" title={v.title}>{v.title}</span> : null}
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <SeverityBadge severity={v.severity} />
                    </TableCell>
                    <TableCell className="px-3 py-2 text-right tabular-nums">{v.cvss?.toFixed(1) ?? '—'}</TableCell>
                    <TableCell className="px-3 py-2">
                      <ScannerPresence scanners={v.scanners} />
                    </TableCell>
                    <TableCell className="px-3 py-2 text-right tabular-nums">{v.imagesAffected}</TableCell>
                    <TableCell className="px-3 py-2 text-right tabular-nums">{v.workloadsAffected}</TableCell>
                    <TableCell className="px-3 py-2">
                      {v.fixAvailable ? (
                        <Badge variant="secondary" className="border border-success-foreground/40 bg-success text-success-foreground">fix available</Badge>
                      ) : (
                        <span className="text-muted-foreground text-xs">no fix</span>
                      )}
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      <ControlChips controls={v.controls} max={2} />
                    </TableCell>
                    <TableCell className="px-3 py-2">
                      {v.url ? (
                        <a href={v.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-muted-foreground text-xs hover:text-foreground">
                          NVD <ExternalLink className="size-3" />
                        </a>
                      ) : (
                        '—'
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          {data && data.total > 0 ? (
            <Pager page={page} pageSize={pageSize} total={data.total} onPage={(p) => update({ page: String(p) }, false)} onPageSize={(s) => update({ pageSize: String(s) })} />
          ) : null}
        </CardContent>
      </Card>
    </>
  );
}
