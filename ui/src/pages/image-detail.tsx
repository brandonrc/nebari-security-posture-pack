import { useMutation } from '@tanstack/react-query';
import { RefreshCw, TriangleAlert } from 'lucide-react';
import { Link, useParams } from 'react-router';
import { api } from '@/api/client';
import { useImage } from '@/api/queries';
import type { ImageDetail } from '@/api/types';
import { SCANNERS } from '@/api/types';
import { FindingsTable } from '@/components/findings-table';
import { CardsSkeleton, CopyButton, EmptyState, ErrorAlert, Meta, PageHeader, errorMessage } from '@/components/page';
import { AgreementDots, ControlChips, GradeRing, SCANNER_LABEL, ScannerStatusIcon, SeverityBadge, SeverityChips, StatusBadge } from '@/components/posture';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsIndicator, TabsList, TabsPanel, TabsTab } from '@/components/ui/tabs';
import { toast } from '@/components/ui/toast';
import { formatAge, formatDateTime, formatDuration, formatRelative } from '@/lib/format';
import { totalCount } from '@/lib/scoring';

function Header({ image }: { image: ImageDetail }) {
  const rescan = useMutation({
    mutationFn: () => api.startScan({ imageIds: [image.id], force: true }),
    onSuccess: (scan) => toast.add({ title: `Rescan queued (scan #${scan.id})`, description: image.ref, type: 'info' }),
    onError: (e) => toast.add({ title: 'Rescan failed', description: errorMessage(e), type: 'error' }),
  });
  return (
    <Card>
      <CardContent className="flex flex-col gap-5 md:flex-row md:items-center">
        <GradeRing score={image.score} grade={image.grade} size={112} stroke={10} />
        <div className="flex min-w-0 flex-1 flex-col gap-3">
          <div className="flex min-w-0 items-center gap-1">
            <h2 className="truncate font-mono font-semibold text-base" title={image.ref}>
              {image.ref}
            </h2>
            <CopyButton value={image.ref} label="Copy image reference" />
          </div>
          <div className="flex min-w-0 items-center gap-1 text-muted-foreground text-xs">
            <span className="truncate font-mono" title={image.digest ?? undefined}>
              {image.digest ?? 'no digest'}
            </span>
            {image.digest ? <CopyButton value={`${image.registry}/${image.repository}@${image.digest}`} label="Copy pinned reference" /> : null}
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <SeverityChips counts={image.counts} />
            <span className="text-muted-foreground text-xs">
              {totalCount(image.counts)} findings · {totalCount(image.fixable)} fixable
            </span>
          </div>
          <div className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3 lg:grid-cols-6">
            <Meta label="Registry">{image.registry}</Meta>
            <Meta label="Tag">{image.tag ?? '—'}</Meta>
            <Meta label="Agreement">
              <AgreementDots value={image.agreementIndex} />
            </Meta>
            <Meta label="Usage">
              {image.workloads} workloads · {image.containers} containers
            </Meta>
            <Meta label="Last scanned">{formatRelative(image.lastScannedAt)}</Meta>
            <Meta label="Source">
              {image.mirrored ? 'mirrored' : 'original ref'}
              {image.confidence === 'low' ? <Badge variant="destructive" className="ml-1">low confidence</Badge> : null}
            </Meta>
          </div>
        </div>
        <div className="flex shrink-0 flex-col gap-2">
          <Button variant="outline" onClick={() => rescan.mutate()} loading={rescan.isPending}>
            <RefreshCw />
            Rescan image
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function UsedBy({ image }: { image: ImageDetail }) {
  return (
    <Table aria-label="Containers using this image">
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="px-3">Namespace</TableHead>
          <TableHead className="px-3">Kind</TableHead>
          <TableHead className="px-3">Name</TableHead>
          <TableHead className="px-3">Container</TableHead>
          <TableHead className="px-3">Pod</TableHead>
          <TableHead className="px-3">Pack</TableHead>
          <TableHead className="px-3">State</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {image.usedBy.length === 0 ? (
          <TableRow>
            <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
              Not referenced by any current pod.
            </TableCell>
          </TableRow>
        ) : (
          image.usedBy.map((u, i) => (
            <TableRow key={`${u.namespace}/${u.name}/${u.pod ?? i}/${u.container}`}>
              <TableCell className="px-3 py-2">
                <Link to={`/images?namespace=${encodeURIComponent(u.namespace)}`} className="underline-offset-4 hover:underline">
                  {u.namespace}
                </Link>
              </TableCell>
              <TableCell className="px-3 py-2 text-muted-foreground">{u.kind}</TableCell>
              <TableCell className="px-3 py-2 font-medium">{u.name}</TableCell>
              <TableCell className="px-3 py-2 font-mono text-xs">{u.container}</TableCell>
              <TableCell className="px-3 py-2 font-mono text-muted-foreground text-xs">{u.pod ?? '—'}</TableCell>
              <TableCell className="px-3 py-2">{u.pack ?? <span className="text-muted-foreground">—</span>}</TableCell>
              <TableCell className="px-3 py-2">
                {u.running ? <StatusBadge status="running" /> : <Badge variant="outline">not running</Badge>}
              </TableCell>
            </TableRow>
          ))
        )}
      </TableBody>
    </Table>
  );
}

function ScannerRuns({ image }: { image: ImageDetail }) {
  const runs = image.scans.length
    ? image.scans
    : SCANNERS.map((s) => ({ scanner: s, ...(image.scanners[s] ?? { status: 'skipped' as const, findings: 0, durationMs: null }) }));
  return (
    <Table aria-label="Scanner runs">
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="px-3">Scanner</TableHead>
          <TableHead className="px-3">Status</TableHead>
          <TableHead className="px-3 text-right">Findings</TableHead>
          <TableHead className="px-3 text-right">Duration</TableHead>
          <TableHead className="px-3">Version</TableHead>
          <TableHead className="px-3">DB</TableHead>
          <TableHead className="px-3">Finished</TableHead>
          <TableHead className="px-3">Error</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {runs.map((r) => {
          const run = r as typeof r & { dbUpdatedAt?: string | null; finishedAt?: string | null; version?: string | null; error?: string | null };
          return (
            <TableRow key={`${run.scanner}-${'scanId' in run ? String(run.scanId) : ''}`}>
              <TableCell className="px-3 py-2 font-medium">{SCANNER_LABEL[run.scanner]}</TableCell>
              <TableCell className="px-3 py-2">
                <span className="inline-flex items-center gap-1.5">
                  <ScannerStatusIcon status={run.status} />
                  {run.status}
                </span>
              </TableCell>
              <TableCell className="px-3 py-2 text-right tabular-nums">{run.findings}</TableCell>
              <TableCell className="px-3 py-2 text-right tabular-nums">{formatDuration(run.durationMs)}</TableCell>
              <TableCell className="px-3 py-2 font-mono text-xs">{run.version ?? '—'}</TableCell>
              <TableCell className="px-3 py-2 text-muted-foreground text-xs">{run.dbUpdatedAt ? formatAge(run.dbUpdatedAt) : '—'}</TableCell>
              <TableCell className="px-3 py-2 text-muted-foreground text-xs">{formatDateTime(run.finishedAt)}</TableCell>
              <TableCell className="max-w-[420px] px-3 py-2">
                {run.error ? <code className="block whitespace-pre-wrap break-words text-destructive-foreground text-xs">{run.error}</code> : <span className="text-muted-foreground">—</span>}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

function Posture({ image }: { image: ImageDetail }) {
  if (!image.postureFindings.length) {
    return <EmptyState title="No failed posture checks">Containers running this image pass every configuration check.</EmptyState>;
  }
  return (
    <Table aria-label="Failed posture checks">
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="px-3">Check</TableHead>
          <TableHead className="px-3">Severity</TableHead>
          <TableHead className="px-3">Workload</TableHead>
          <TableHead className="px-3">Container</TableHead>
          <TableHead className="px-3">Detail</TableHead>
          <TableHead className="px-3">Controls</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {image.postureFindings.map((p, i) => (
          <TableRow key={`${p.checkId}-${p.namespace}-${p.name}-${i}`}>
            <TableCell className="px-3 py-2">
              <Link to={`/checks/${encodeURIComponent(p.checkId)}`} className="font-medium underline-offset-4 hover:underline">
                {p.title ?? p.checkId}
              </Link>
            </TableCell>
            <TableCell className="px-3 py-2">
              <SeverityBadge severity={p.severity} />
            </TableCell>
            <TableCell className="px-3 py-2">
              <span className="text-muted-foreground">{p.namespace}/</span>
              {p.name}
              <span className="ml-1 text-muted-foreground text-xs">{p.kind}</span>
            </TableCell>
            <TableCell className="px-3 py-2 font-mono text-xs">{p.container ?? '—'}</TableCell>
            <TableCell className="px-3 py-2 text-muted-foreground text-xs">{p.detail ?? '—'}</TableCell>
            <TableCell className="px-3 py-2">
              <ControlChips controls={p.controls} />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function ImageDetailPage() {
  const { id = '' } = useParams();
  const { data: image, error, isLoading, refetch } = useImage(id);
  const failedScanners = image ? SCANNERS.filter((s) => image.scanners[s] && image.scanners[s]?.status !== 'ok') : [];

  return (
    <>
      <PageHeader
        title={image ? image.repository.split('/').pop() : 'Image'}
        crumbs={[{ label: 'Images', to: '/images' }, { label: image?.repository ?? id }]}
      />
      {error ? <ErrorAlert error={error} onRetry={() => void refetch()} /> : null}
      {isLoading ? <CardsSkeleton count={2} className="xl:grid-cols-2" /> : null}
      {image ? (
        <>
          <Header image={image} />
          {image.warnings.length || failedScanners.length ? (
            <Alert variant="warning">
              <TriangleAlert />
              <AlertTitle>{image.score === null ? 'No scanner succeeded — image is not scored' : 'Partial scan coverage'}</AlertTitle>
              <AlertDescription>
                <ul className="list-disc pl-4">
                  {failedScanners.map((s) => (
                    <li key={s}>
                      {SCANNER_LABEL[s]}: {image.scanners[s]?.status} — {image.scanners[s]?.error ?? 'no detail'}
                    </li>
                  ))}
                  {image.warnings.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          ) : null}
          <Card>
            <CardContent>
              <Tabs defaultValue="findings">
                <TabsList variant="underline" aria-label="Image detail sections">
                  <TabsTab value="findings">
                    Findings <Badge variant="secondary">{image.findings.length}</Badge>
                  </TabsTab>
                  <TabsTab value="used-by">
                    Used by <Badge variant="secondary">{image.usedBy.length}</Badge>
                  </TabsTab>
                  <TabsTab value="runs">Scanner runs</TabsTab>
                  <TabsTab value="posture">
                    Posture <Badge variant={image.postureFindings.length ? 'destructive' : 'secondary'}>{image.postureFindings.length}</Badge>
                  </TabsTab>
                  <TabsIndicator />
                </TabsList>
                <TabsPanel value="findings">
                  <FindingsTable findings={image.findings} scanners={image.scanners} />
                </TabsPanel>
                <TabsPanel value="used-by">
                  <UsedBy image={image} />
                </TabsPanel>
                <TabsPanel value="runs">
                  <ScannerRuns image={image} />
                </TabsPanel>
                <TabsPanel value="posture">
                  <Posture image={image} />
                </TabsPanel>
              </Tabs>
            </CardContent>
          </Card>
        </>
      ) : null}
    </>
  );
}
