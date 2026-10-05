import type * as React from 'react';
import { useCallback, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Download, RefreshCw, TriangleAlert } from 'lucide-react';
import { Link, useParams, useSearchParams } from 'react-router';
import { api } from '@/api/client';
import { useImage } from '@/api/queries';
import { useCapabilities } from '@/capabilities';
import type { ImageDetail } from '@/api/types';
import { SCANNERS } from '@/api/types';
import { ImageStigTab } from '@/components/image-stig';
import { StigScore } from '@/components/stig';
import { DEFAULT_FINDINGS_QUERY, FindingsTable, type FindingsQuery } from '@/components/findings-table';
import { Pager, useClientPagination } from '@/components/table-kit';
import { CardsSkeleton, CopyButton, EmptyState, ErrorAlert, Meta, PageHeader, errorMessage } from '@/components/page';
import { AgreementDots, ControlChips, GradeRing, SCANNER_LABEL, ScannerStatusIcon, SeverityBadge, SeverityChips, StatusBadge } from '@/components/posture';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsIndicator, TabsList, TabsPanel, TabsTab } from '@/components/ui/tabs';
import { toast } from '@/components/ui/toast';
import { ProvenanceGlyph, SbomGlyph, SignatureGlyph, signatureState, UpdateIndicator } from '@/components/supply-chain';
import { formatAge, formatDateTime, formatDuration, formatRelative } from '@/lib/format';
import { totalCount } from '@/lib/scoring';
import { latestTag, supplyChainScore, updateLevel } from '@/lib/supply-chain';
import { gradeClass } from '@/lib/severity-styles';
import { cn } from '@/lib/utils';

function Header({ image, pv }: { image: ImageDetail; pv: boolean }) {
  const rescan = useMutation({
    mutationFn: () => api.startScan({ imageIds: [image.id], force: true }),
    onSuccess: (scan) => toast.add({ title: `Rescan queued (scan #${scan.id})`, description: image.ref, type: 'info' }),
    onError: (e) => toast.add({ title: 'Rescan failed', description: errorMessage(e), type: 'error' }),
  });
  return (
    <Card>
      <CardContent className="flex flex-col gap-5 md:flex-row md:items-center">
        {pv ? (
          <GradeRing score={image.provenance?.score ?? null} grade={image.provenance?.grade ?? '?'} size={112} stroke={10} />
        ) : (
          <GradeRing score={image.score} grade={image.grade} size={112} stroke={10} />
        )}
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
          {pv ? null : (
          <div className="flex flex-wrap items-center gap-3">
            <SeverityChips counts={image.counts} />
            <span className="text-muted-foreground text-xs">
              {totalCount(image.counts)} findings · {totalCount(image.fixable)} fixable
            </span>
          </div>
          )}
          <div className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3 lg:grid-cols-6">
            <Meta label="Registry">{image.registry}</Meta>
            <Meta label="Tag">{image.tag ?? '—'}</Meta>
            {pv ? null : (
              <Meta label="Agreement">
                <AgreementDots value={image.agreementIndex} />
              </Meta>
            )}
            <Meta label="Usage">
              {image.workloads} workloads · {image.containers} containers
            </Meta>
            <Meta label={pv ? 'Collected' : 'Last scanned'}>{formatRelative(image.lastScannedAt)}</Meta>
            {pv ? null : (
              <Meta label="Source">
                {image.mirrored ? 'mirrored' : 'original ref'}
                {image.confidence === 'low' ? <Badge variant="destructive" className="ml-1">low confidence</Badge> : null}
              </Meta>
            )}
          </div>
        </div>
        {pv ? null : (
          <div className="flex shrink-0 flex-col gap-2">
            <Button variant="outline" onClick={() => rescan.mutate()} loading={rescan.isPending}>
              <RefreshCw />
              Rescan image
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function UsedBy({ image }: { image: ImageDetail }) {
  const { pageRows, pagerProps } = useClientPagination(image.usedBy, { resetKey: image.id });
  return (
    <div className="flex flex-col gap-3">
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
          pageRows.map((u, i) => (
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
    {image.usedBy.length > pagerProps.pageSizeOptions[0] ? <Pager {...pagerProps} /> : null}
    </div>
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

function SupplyChainTabBadge({ image }: { image: ImageDetail }) {
  const sc = supplyChainScore(image.provenance, { tag: image.tag });
  if (!sc) return null;
  return (
    <Badge variant="secondary" className={cn('border', gradeClass[sc.grade])} aria-label={`supply-chain grade ${sc.grade}`}>
      {sc.grade}
    </Badge>
  );
}

function Fact({ label, glyph, children }: { label: string; glyph?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-1.5 rounded-md border border-border bg-background p-3">
      <span className="flex items-center gap-1.5 text-[11px] text-muted-foreground uppercase tracking-wide">
        {glyph}
        {label}
      </span>
      <div className="min-w-0 text-sm">{children}</div>
    </div>
  );
}

function SupplyChain({ image }: { image: ImageDetail }) {
  const p = image.provenance;
  if (!p) {
    return (
      <EmptyState title="No supply-chain data">
        Signature, SBOM, provenance and update checks haven’t run for this image yet (or are disabled in Settings → Supply chain).
      </EmptyState>
    );
  }
  const sc = supplyChainScore(p, { tag: image.tag });
  const sig = p.signature;
  const level = updateLevel(p.update);
  return (
    <div className="flex flex-col gap-5 pt-2 lg:flex-row">
      <div className="flex shrink-0 flex-col items-center gap-3 lg:w-64">
        <GradeRing score={sc?.score ?? null} grade={sc?.grade ?? '?'} size={112} stroke={10} />
        <p className="text-center text-muted-foreground text-xs">
          Supply-chain score · weighs 15% of the cluster score
          {p.checkedAt ? <span className="block">checked {formatRelative(p.checkedAt)}</span> : null}
        </p>
        <Table aria-label="Supply-chain score deductions" className="text-sm">
          <TableBody>
            <TableRow className="hover:bg-transparent">
              <TableCell className="px-2 py-1.5">Start</TableCell>
              <TableCell className="px-2 py-1.5 text-right tabular-nums">100</TableCell>
            </TableRow>
            {sc?.deductions.length ? (
              sc.deductions.map((d) => (
                <TableRow key={d.reason} className="hover:bg-transparent">
                  <TableCell className="whitespace-normal px-2 py-1.5 text-muted-foreground text-xs">{d.reason}</TableCell>
                  <TableCell className="px-2 py-1.5 text-right text-destructive-foreground tabular-nums">−{Math.abs(d.points)}</TableCell>
                </TableRow>
              ))
            ) : (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={2} className="px-2 py-1.5 text-success-foreground text-xs">No deductions</TableCell>
              </TableRow>
            )}
            <TableRow className="hover:bg-transparent">
              <TableCell className="px-2 py-1.5 font-medium">Score</TableCell>
              <TableCell className="px-2 py-1.5 text-right font-medium tabular-nums">{sc ? sc.score.toFixed(0) : '—'}</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </div>
      <div className="grid min-w-0 flex-1 content-start gap-3 sm:grid-cols-2">
        <Fact label="Signature" glyph={<SignatureGlyph provenance={p} />}>
          {sig ? (
            <>
              <span className="font-medium capitalize">{signatureState(p).label}</span>
              {sig.mode ? <span className="ml-1 text-muted-foreground text-xs">({sig.mode})</span> : null}
              {sig.error ? <code className="mt-1 block whitespace-pre-wrap break-words text-destructive-foreground text-xs">{sig.error}</code> : null}
            </>
          ) : (
            <span className="text-muted-foreground">Not checked</span>
          )}
        </Fact>
        <Fact label="SBOM" glyph={<SbomGlyph provenance={p} />}>
          {p.sbom ? (
            p.sbom.hasSBOM ? (
              <span className="flex flex-wrap items-center gap-2">
                <span className="font-medium">Attached</span>
                {p.sbom.format ? <Badge variant="outline" className="font-mono">{p.sbom.format}</Badge> : null}
                {p.sbom.downloadUrl ? (
                  <Button size="xs" variant="outline" render={<a href={p.sbom.downloadUrl} download />}>
                    <Download />
                    Download
                  </Button>
                ) : null}
              </span>
            ) : (
              <span className="font-medium">No SBOM attestation</span>
            )
          ) : (
            <span className="text-muted-foreground">Not checked</span>
          )}
        </Fact>
        <Fact label="SLSA provenance" glyph={<ProvenanceGlyph provenance={p} />}>
          {p.provenance ? (
            p.provenance.hasProvenance ? (
              <>
                <span className="font-medium">Attestation present</span>
                {p.provenance.predicateType ? <code className="mt-1 block break-all text-muted-foreground text-xs">{p.provenance.predicateType}</code> : null}
                {p.provenance.builder ? <span className="mt-0.5 block break-all text-muted-foreground text-xs">builder {p.provenance.builder}</span> : null}
              </>
            ) : (
              <span className="font-medium">No provenance attestation</span>
            )
          ) : (
            <span className="text-muted-foreground">Not checked</span>
          )}
        </Fact>
        <Fact label="Updates">
          {p.update ? (
            <span className="flex flex-col gap-1">
              <span className="flex flex-wrap items-center gap-2">
                <span className="font-mono">{p.update.currentTag}</span>
                {level ? (
                  <>
                    <span className="text-muted-foreground">→</span>
                    <UpdateIndicator update={p.update} />
                  </>
                ) : (
                  <span className="text-success-foreground text-xs">up to date</span>
                )}
              </span>
              {level ? (
                <span className={cn('text-xs', level === 'major' ? 'text-destructive-foreground' : 'text-muted-foreground')}>
                  {level} update{latestTag(p.update) ? ` to ${latestTag(p.update)}` : ''}
                  {p.update.latestInMajor && p.update.latestInMajor !== latestTag(p.update) ? ` · latest in current major ${p.update.latestInMajor}` : ''}
                </span>
              ) : null}
            </span>
          ) : (
            <span className="text-muted-foreground">Not checked</span>
          )}
        </Fact>
        {p.mutableTag ? (
          <Fact label="Tag pinning">
            <span className="text-warning-foreground">Mutable tag without a digest pin</span>
          </Fact>
        ) : null}
      </div>
    </div>
  );
}

const TABS = ['findings', 'used-by', 'runs', 'posture', 'supply-chain', 'stig'] as const;
/** provenance mode has no scanner data: only the collector's view of the image */
const PROVENANCE_TABS = ['used-by', 'supply-chain'] as const;

export function ImageDetailPage() {
  const [params, setParams] = useSearchParams();
  const pv = useCapabilities().mode === 'provenance';
  const defaultTab = pv ? 'supply-chain' : 'findings';
  const tabParam = params.get('tab') ?? defaultTab;
  const tab = ((pv ? PROVENANCE_TABS : TABS) as readonly string[]).includes(tabParam) ? tabParam : defaultTab;
  const { id = '' } = useParams();
  // findings tab state = the server-side findings query; back to defaults on another image
  const [findingsQuery, setFindingsQuery] = useState<{ id: string; q: FindingsQuery }>({ id, q: DEFAULT_FINDINGS_QUERY });
  const fq = findingsQuery.id === id ? findingsQuery.q : DEFAULT_FINDINGS_QUERY;
  const onFindingsQuery = useCallback(
    (patch: Partial<FindingsQuery>) =>
      setFindingsQuery((prev) => {
        const base = prev.id === id ? prev.q : DEFAULT_FINDINGS_QUERY;
        return { id, q: { ...base, ...patch, page: patch.page ?? 1 } };
      }),
    [id],
  );
  const { data: image, error, isLoading, isPlaceholderData, refetch } = useImage(id, fq);
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
          <Header image={image} pv={pv} />
          {image.warnings.length || failedScanners.length ? (
            <Alert variant="warning">
              <TriangleAlert />
              <AlertTitle>{pv ? 'Collector warnings' : image.score === null ? 'No scanner succeeded — image is not scored' : 'Partial scan coverage'}</AlertTitle>
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
              <Tabs
                value={tab}
                onValueChange={(v) =>
                  setParams(
                    (prev) => {
                      const next = new URLSearchParams(prev);
                      if (v === defaultTab) next.delete('tab');
                      else next.set('tab', String(v));
                      return next;
                    },
                    { replace: true },
                  )
                }
              >
                <TabsList variant="underline" aria-label="Image detail sections">
                  {pv ? null : (
                    <TabsTab value="findings">
                      Findings <Badge variant="secondary">{(image.findingsSummary?.total ?? image.findingsTotal ?? image.findings.length).toLocaleString()}</Badge>
                    </TabsTab>
                  )}
                  <TabsTab value="used-by">
                    Used by <Badge variant="secondary">{image.usedBy.length}</Badge>
                  </TabsTab>
                  {pv ? null : (
                    <>
                      <TabsTab value="runs">Scanner runs</TabsTab>
                      <TabsTab value="posture">
                        Posture <Badge variant={image.postureFindings.length ? 'destructive' : 'secondary'}>{image.postureFindings.length}</Badge>
                      </TabsTab>
                    </>
                  )}
                  <TabsTab value="supply-chain">
                    Supply chain
                    {image.provenance ? <SupplyChainTabBadge image={image} /> : null}
                  </TabsTab>
                  {pv ? null : (
                    <TabsTab value="stig">
                      STIG
                      {image.stig !== undefined ? <StigScore score={image.stig?.score ?? null} /> : null}
                    </TabsTab>
                  )}
                  <TabsIndicator />
                </TabsList>
                <TabsPanel value="findings">
                  <FindingsTable image={image} query={fq} onQueryChange={onFindingsQuery} loading={isPlaceholderData} />
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
                <TabsPanel value="supply-chain">
                  <SupplyChain image={image} />
                </TabsPanel>
                {pv ? null : (
                  <TabsPanel value="stig">
                    <ImageStigTab key={image.id} imageId={image.id} />
                  </TabsPanel>
                )}
              </Tabs>
            </CardContent>
          </Card>
        </>
      ) : null}
    </>
  );
}
