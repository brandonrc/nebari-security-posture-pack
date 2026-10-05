import { Download, Eye, FileJson, FileSpreadsheet, FileText } from 'lucide-react';
import { downloadFile, provenanceApi } from '@/api/client';
import { reportDeltas, useDataset } from '@/api/provenance-adapter';
import type { ProvenanceMe } from '@/api/provenance-adapter';
import type { PcReportEntry } from '@/api/provenance-report';
import { useProvenanceReports, useSwitchDataset } from '@/api/provenance-queries';
import { useMe } from '@/api/queries';
import { EmptyState, ErrorAlert, errorMessage, PageHeader } from '@/components/page';
import { DatasetBanner } from '@/components/provenance';
import { SkeletonRows, StateRow } from '@/components/table-kit';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { toast } from '@/components/ui/toast';
import { formatDateTime, formatRelative } from '@/lib/format';



async function save(url: string, name: string) {
  try {
    await downloadFile(url, name);
  } catch (error) {
    toast.add({ title: 'Download failed', description: errorMessage(error), type: 'error' });
  }
}

function base(filename: string | null) {
  return (filename ?? 'provenance-latest.json').replace(/\.json$/, '');
}

/** JSON / CSV / Markdown downloads for one report (`null` = latest). */
export function ReportDownloads({ filename, compact = false }: { filename: string | null; compact?: boolean }) {
  const label = filename ?? 'latest report';
  return (
    <span className="flex flex-wrap items-center gap-1">
      <Button variant="ghost" size="sm" aria-label={`Download ${label} as JSON`} onClick={() => void save(provenanceApi.reportUrl(filename), `${base(filename)}.json`)}>
        <FileJson />
        {compact ? null : 'JSON'}
      </Button>
      <Button variant="ghost" size="sm" aria-label={`Export ${label} as CSV`} onClick={() => void save(provenanceApi.exportUrl('csv', filename), `${base(filename)}.csv`)}>
        <FileSpreadsheet />
        {compact ? null : 'CSV'}
      </Button>
      <Button
        variant="ghost"
        size="sm"
        aria-label={`Export ${label} as Markdown`}
        onClick={() => void save(provenanceApi.exportUrl('markdown', filename), `${base(filename)}.md`)}
      >
        <FileText />
        {compact ? null : 'Markdown'}
      </Button>
    </span>
  );
}

function Delta({ value }: { value: number | null | undefined }) {
  if (value === null || value === undefined) return <span className="text-muted-foreground">—</span>;
  if (value === 0) return <span className="text-muted-foreground">±0</span>;
  return <span className={value > 0 ? 'text-warning-foreground' : 'text-success-foreground'}>{value > 0 ? `+${value}` : value}</span>;
}

/** Reports in provenance mode: the collector's timestamped reports, newest first. */
export function ProvenanceReportsPage() {
  const { data, error, isLoading, refetch } = useProvenanceReports();
  const me = useMe().data as ProvenanceMe | undefined;
  const dataset = useDataset();
  const switchTo = useSwitchDataset();
  const rows: PcReportEntry[] = data ?? [];
  const deltas = me?.features?.timelineDeltas ? reportDeltas(rows) : null;

  return (
    <>
      <PageHeader
        title="Reports"
        description="Every collector run writes a timestamped report. View one to load it into Images, Supply chain and Overview, or download it."
        actions={
          <span className="flex items-center gap-2 text-muted-foreground text-sm">
            <Download className="size-4" aria-hidden="true" /> Latest:
            <ReportDownloads filename={null} />
          </span>
        }
      />
      <DatasetBanner />
      {error ? <ErrorAlert error={error} onRetry={() => void refetch()} /> : null}
      <Card>
        <CardContent>
          <Table aria-label="Reports" aria-busy={isLoading || undefined}>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="px-3">Generated</TableHead>
                <TableHead className="px-3">Cluster</TableHead>
                <TableHead className="px-3 text-right">Images</TableHead>
                {deltas ? <TableHead className="px-3 text-right">Δ</TableHead> : null}
                <TableHead className="px-3 text-right">Signed / verified</TableHead>
                <TableHead className="px-3 text-right">SBOM · SLSA</TableHead>
                <TableHead className="px-3 text-right">Updates</TableHead>
                <TableHead className="px-3">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <SkeletonRows cols={deltas ? 8 : 7} />
              ) : !rows.length ? (
                <StateRow cols={deltas ? 8 : 7}>
                  <EmptyState title="No reports yet">The collector writes one per run; trigger a scan or wait for the CronJob.</EmptyState>
                </StateRow>
              ) : (
                rows.map((r, i) => {
                  const s = r.summary;
                  const viewing = dataset === r.filename || (dataset === null && i === 0);
                  return (
                    <TableRow key={r.filename} data-state={viewing ? 'selected' : undefined}>
                      <TableCell className="px-3 py-2">
                        <span className="block whitespace-nowrap">{formatDateTime(r.generatedAt)}</span>
                        <span className="block font-mono text-[11px] text-muted-foreground">{r.filename}</span>
                      </TableCell>
                      <TableCell className="px-3 py-2">{r.clusterName ?? '—'}</TableCell>
                      <TableCell className="px-3 py-2 text-right tabular-nums" title={`${s?.totalImages ?? 0} containers`}>
                        {s?.uniqueImages ?? 0}
                      </TableCell>
                      {deltas ? (
                        <TableCell className="px-3 py-2 text-right tabular-nums">
                          <Delta value={deltas.get(r.filename)} />
                        </TableCell>
                      ) : null}
                      <TableCell className="px-3 py-2 text-right tabular-nums">
                        {s?.signedImages ?? 0} / {s?.verifiedImages ?? 0}
                      </TableCell>
                      <TableCell className="px-3 py-2 text-right tabular-nums">
                        {s?.imagesWithSBOM ?? 0} · {s?.imagesWithProvenance ?? 0}
                      </TableCell>
                      <TableCell className="px-3 py-2 text-right tabular-nums">
                        {s?.imagesWithUpdates ?? 0}
                        {s?.helmReleasesWithUpdates ? <span className="text-muted-foreground text-xs"> +{s.helmReleasesWithUpdates} Helm</span> : null}
                      </TableCell>
                      <TableCell className="px-3 py-2">
                        <span className="flex flex-wrap items-center gap-1">
                          {viewing ? (
                            <Badge variant="outline">{dataset === null ? 'Latest · viewing' : 'Viewing'}</Badge>
                          ) : (
                            <Button variant="outline" size="sm" aria-label={`View report ${r.filename}`} onClick={() => switchTo(i === 0 ? null : r.filename)}>
                              <Eye />
                              View
                            </Button>
                          )}
                          <ReportDownloads filename={r.filename} compact />
                        </span>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
          {rows.length ? <p className="mt-3 text-muted-foreground text-xs">Newest {formatRelative(rows[0].generatedAt)}.</p> : null}
        </CardContent>
      </Card>
    </>
  );
}
