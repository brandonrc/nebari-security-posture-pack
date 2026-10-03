import { ArrowRight, BadgeCheck, FileCheck, PackageCheck, ShieldCheck, ShieldHalf, Ship } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { useHelmReleases, useImages, useSummary, useSupplyChain } from '@/api/queries';
import type { HelmRelease, ImageSummary, SupplyChainSummary } from '@/api/types';
import { CardsSkeleton, EmptyState, ErrorAlert, errorMessage, PageHeader } from '@/components/page';
import { GradeRing, StatusBadge } from '@/components/posture';
import { SignatureGlyph, signatureState, UpdateIndicator } from '@/components/supply-chain';
import { Button } from '@/components/ui/button';
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumnDef } from '@/components/ui/data-table';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { asRows } from '@/lib/format';
import { gradeForScore } from '@/lib/scoring';
import { latestTag, percent, updateLevel } from '@/lib/supply-chain';
import { cn } from '@/lib/utils';

type HelmRow = HelmRelease & Record<string, unknown>;
const LEVEL_RANK = { major: 3, minor: 2, patch: 1 } as const;

/** Fallback when `GET /supply-chain` isn't available: derive the summary from images + releases. */
function deriveSummary(images: ImageSummary[], releases: HelmRelease[], score: number | null | undefined): SupplyChainSummary {
  const p = images.map((i) => i.provenance);
  const s = score ?? null;
  return {
    signed: p.filter((x) => x?.signature?.signed).length,
    verified: p.filter((x) => x?.signature?.verified).length,
    withSbom: p.filter((x) => x?.sbom?.hasSBOM).length,
    withProvenance: p.filter((x) => x?.provenance?.hasProvenance).length,
    withUpdates: p.filter((x) => x?.update?.updateAvailable).length,
    unique: images.length,
    helmReleases: releases.length,
    helmWithUpdates: releases.filter((r) => r.update?.updateAvailable).length,
    score: s,
    grade: gradeForScore(s),
  };
}

function Meter({ value }: { value: number | null }) {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted" aria-hidden="true">
      <div className="h-full rounded-full bg-primary motion-safe:transition-[width]" style={{ width: `${Math.max(0, Math.min(100, value ?? 0))}%` }} />
    </div>
  );
}

function StatTile({ label, icon, value, of, unit = 'images', pct = true }: { label: string; icon: ReactNode; value: number; of: number; unit?: string; pct?: boolean }) {
  const p = percent(value, of);
  return (
    <Card size="sm">
      <CardContent className="flex flex-col gap-2">
        <span className="flex items-center gap-1.5 text-muted-foreground text-xs uppercase tracking-wide [&_svg]:size-3.5">
          {icon}
          {label}
        </span>
        <span className="font-semibold text-3xl tabular-nums tracking-tight">{pct ? (p === null ? '—' : `${p.toFixed(0)}%`) : value.toLocaleString()}</span>
        {pct ? <Meter value={p} /> : null}
        <span className="text-muted-foreground text-xs tabular-nums">
          {value.toLocaleString()} of {of.toLocaleString()} {unit}
        </span>
      </CardContent>
    </Card>
  );
}

const helmColumns: DataTableColumnDef<HelmRow>[] = [
  {
    id: 'releaseName',
    accessorFn: (r) => `${r.releaseName} ${r.namespace} ${r.chart}`,
    header: 'Release',
    filterFn: 'includesString',
    sortFn: 'text',
    cell: ({ row }) => <span className="font-medium">{row.original.releaseName}</span>,
  },
  {
    id: 'namespace',
    accessorFn: (r) => r.namespace,
    header: 'Namespace',
    sortFn: 'text',
    cell: ({ row }) => (
      <Link to={`/images?namespace=${encodeURIComponent(row.original.namespace)}`} className="underline-offset-4 hover:underline">
        {row.original.namespace}
      </Link>
    ),
  },
  { id: 'chart', accessorFn: (r) => r.chart, header: 'Chart', sortFn: 'text', cell: ({ row }) => <span className="font-mono text-xs">{row.original.chart}</span> },
  {
    id: 'version',
    accessorFn: (r) => LEVEL_RANK[updateLevel(r.update) ?? 'patch'] * (r.update?.updateAvailable ? 1 : 0),
    header: 'Installed → latest',
    cell: ({ row }) => (
      <span className="flex items-center gap-2">
        <span className="font-mono text-xs">{row.original.version}</span>
        {row.original.update?.updateAvailable ? (
          <UpdateIndicator update={row.original.update} />
        ) : (
          <span className="text-muted-foreground text-xs">{row.original.update ? 'up to date' : 'not checked'}</span>
        )}
      </span>
    ),
  },
  { id: 'appVersion', accessorFn: (r) => r.appVersion ?? '', header: 'App version', sortFn: 'text', cell: ({ row }) => <span className="font-mono text-muted-foreground text-xs">{row.original.appVersion || '—'}</span> },
  { id: 'status', accessorFn: (r) => r.status, header: 'Status', sortFn: 'text', cell: ({ row }) => <StatusBadge status={row.original.status} /> },
];

function ImageLink({ image }: { image: ImageSummary }) {
  return (
    <Link to={`/images/${encodeURIComponent(image.id)}?tab=supply-chain`} className="block max-w-[180px] truncate font-mono 2xl:max-w-[300px] text-xs underline-offset-4 hover:underline" title={image.ref}>
      {image.ref}
    </Link>
  );
}

function UnsignedTable({ images }: { images: ImageSummary[] }) {
  if (!images.length) return <EmptyState title="Every image is signed and verified" />;
  return (
    <Table aria-label="Unsigned images">
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="px-3">Image</TableHead>
          <TableHead className="px-3">Signature</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {images.map((i) => (
          <TableRow key={i.id}>
            <TableCell className="px-3 py-2">
              <ImageLink image={i} />
            </TableCell>
            <TableCell className="px-3 py-2">
              <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs">
                <SignatureGlyph provenance={i.provenance} />
                {signatureState(i.provenance).label}
              </span>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function OutdatedTable({ images }: { images: ImageSummary[] }) {
  if (!images.length) return <EmptyState title="All images are on their latest tag" />;
  return (
    <Table aria-label="Outdated images">
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="px-3">Image</TableHead>
          <TableHead className="px-3">Current</TableHead>
          <TableHead className="px-3">Latest</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {images.map((i) => (
          <TableRow key={i.id}>
            <TableCell className="px-3 py-2">
              <ImageLink image={i} />
            </TableCell>
            <TableCell className="max-w-28 truncate px-3 py-2 font-mono text-muted-foreground text-xs">{i.provenance?.update?.currentTag ?? i.tag ?? '—'}</TableCell>
            <TableCell className="px-3 py-2">
              <UpdateIndicator update={i.provenance?.update} className="max-w-24" />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function SupplyChainPage() {
  const sc = useSupplyChain();
  const summary = useSummary();
  const helm = useHelmReleases();
  const imagesQuery = useImages({ pageSize: 500, sort: 'ref', order: 'asc' });
  const images = imagesQuery.data?.items ?? [];
  const releases = helm.data ?? [];
  const data: SupplyChainSummary | null = sc.data ?? (imagesQuery.data ? deriveSummary(images, releases, summary.data?.supplyChainScore) : null);
  const hasProvenance = images.some((i) => i.provenance);

  const unsigned = images.filter((i) => i.provenance?.signature && !i.provenance.signature.verified);
  unsigned.sort((a, b) => Number(a.provenance?.signature?.signed) - Number(b.provenance?.signature?.signed) || b.workloads - a.workloads);
  const outdated = images.filter((i) => updateLevel(i.provenance?.update));
  outdated.sort((a, b) => LEVEL_RANK[updateLevel(b.provenance?.update) ?? 'patch'] - LEVEL_RANK[updateLevel(a.provenance?.update) ?? 'patch'] || (latestTag(a.provenance?.update) ?? '').localeCompare(latestTag(b.provenance?.update) ?? ''));
  const loading = (sc.isLoading && imagesQuery.isLoading) || (!data && imagesQuery.isLoading);

  return (
    <>
      <PageHeader title="Supply chain" description="Image signatures (cosign), SBOM and SLSA provenance attestations, and available updates for images and Helm releases." />
      {imagesQuery.error ? <ErrorAlert error={imagesQuery.error} onRetry={() => void imagesQuery.refetch()} /> : null}
      {loading ? <CardsSkeleton count={3} /> : null}
      {data ? (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
          <Card>
            <CardHeader>
              <CardTitle>Supply-chain score</CardTitle>
              <CardDescription>Container-weighted mean; 15% of the cluster score</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col items-center gap-3">
              <GradeRing score={data.score} grade={data.grade ?? gradeForScore(data.score)} size={140} stroke={12} />
              <p className="text-center text-muted-foreground text-xs">
                Per image: −40 unsigned (−20 unverified), −20 no SBOM, −15 no provenance, −15 update (−25 major), −10 mutable tag.
              </p>
            </CardContent>
          </Card>
          <div className="grid grid-cols-2 gap-4 xl:grid-cols-3">
            <StatTile label="Signed" icon={<ShieldHalf />} value={data.signed} of={data.unique} />
            <StatTile label="Verified" icon={<ShieldCheck />} value={data.verified} of={data.unique} />
            <StatTile label="SBOM" icon={<FileCheck />} value={data.withSbom} of={data.unique} />
            <StatTile label="Provenance" icon={<BadgeCheck />} value={data.withProvenance} of={data.unique} />
            <StatTile label="Images with updates" icon={<PackageCheck />} value={data.withUpdates} of={data.unique} pct={false} />
            <StatTile label="Helm releases with updates" icon={<Ship />} value={data.helmWithUpdates} of={data.helmReleases} unit="releases" pct={false} />
          </div>
        </div>
      ) : null}
      {!loading && imagesQuery.data && !hasProvenance && !sc.data ? (
        <Card>
          <CardContent>
            <EmptyState title="No supply-chain data yet">
              The provenance stage hasn’t reported for any image. It runs after inventory on the next scan when enabled in Settings → Supply chain.
            </EmptyState>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Helm releases</CardTitle>
          <CardDescription>From <code className="font-mono">sh.helm.release.v1.*</code> secrets; chart versions compared against their repository index.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable<HelmRow>
            ariaLabel="Helm releases"
            columns={helmColumns}
            data={asRows(releases)}
            getRowId={(r) => `${r.namespace}/${r.releaseName}`}
            filterColumnId="releaseName"
            filterPlaceholder="Filter releases…"
            selectable={false}
            showPagination={releases.length > 25}
            initialPageSize={25}
            loading={helm.isLoading}
            error={helm.error ? errorMessage(helm.error) : undefined}
            onRetry={() => void helm.refetch()}
            emptyTitle="No Helm releases"
            emptyDescription="Helm release discovery is disabled or no releases were found."
          />
        </CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Unsigned or unverified images</CardTitle>
            <CardDescription>{unsigned.length} of {images.length} images lack a verified cosign signature</CardDescription>
          </CardHeader>
          <CardContent className={cn(imagesQuery.isLoading && 'opacity-60')}>
            <UnsignedTable images={unsigned} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Outdated images</CardTitle>
            <CardDescription>Newer tags available (major first)</CardDescription>
            <CardAction>
              <Button variant="ghost" size="sm" render={<Link to="/images" />}>
                All images
                <ArrowRight />
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className={cn(imagesQuery.isLoading && 'opacity-60')}>
            <OutdatedTable images={outdated} />
          </CardContent>
        </Card>
      </div>
    </>
  );
}
