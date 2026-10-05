import { ArrowRight, BadgeCheck, FileCheck, PackageCheck, ShieldCheck, ShieldHalf, Ship, TriangleAlert } from 'lucide-react';
import { Link } from 'react-router';
import { useProvenanceReport, useProvenanceReports } from '@/api/provenance-queries';
import { CardsSkeleton, ErrorAlert, Meta, PageHeader } from '@/components/page';
import { GradeRing } from '@/components/posture';
import { DatasetBanner, RunScanButton, ScanJobStatus } from '@/components/provenance';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { formatDateTime, formatRelative } from '@/lib/format';
import { StatTile } from '@/pages/supply-chain';

/** Overview in provenance mode: the collector's report stats only (no vulnerability or posture data). */
export function ProvenanceOverviewPage() {
  const { data, error, isLoading, refetch } = useProvenanceReport();
  const reports = useProvenanceReports();
  const sc = data?.supplyChain;
  const meta = data?.meta;

  return (
    <>
      <PageHeader
        title="Overview"
        description="Image signatures, SBOM and SLSA provenance attestations and available updates, from the provenance collector."
        actions={<RunScanButton />}
      >
        <ScanJobStatus />
      </PageHeader>
      <DatasetBanner />
      {error ? <ErrorAlert error={error} onRetry={() => void refetch()} title="Couldn’t load the provenance report" /> : null}
      {isLoading ? <CardsSkeleton count={3} /> : null}
      {sc && meta ? (
        <>
          <div className="grid gap-4 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
            <Card>
              <CardHeader>
                <CardTitle>Supply-chain score</CardTitle>
                <CardDescription>Container-weighted mean of the per-image scores</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col items-center gap-3">
                <GradeRing score={sc.score} grade={sc.grade} size={140} stroke={12} />
                <p className="text-center text-muted-foreground text-xs">
                  Per image: −40 unsigned (−20 unverified), −20 no SBOM, −15 no provenance, −15 update (−25 major), −10 mutable tag. Checks the
                  collector didn’t run cost nothing.
                </p>
              </CardContent>
            </Card>
            <div className="grid grid-cols-2 gap-4 xl:grid-cols-3">
              <StatTile label="Signed" icon={<ShieldHalf />} value={sc.signed} of={sc.unique} />
              <StatTile label="Verified" icon={<ShieldCheck />} value={sc.verified} of={sc.unique} />
              <StatTile label="SBOM" icon={<FileCheck />} value={sc.withSbom} of={sc.unique} />
              <StatTile label="Provenance" icon={<BadgeCheck />} value={sc.withProvenance} of={sc.unique} />
              <StatTile label="Images with updates" icon={<PackageCheck />} value={sc.withUpdates} of={sc.unique} pct={false} />
              <StatTile label="Helm releases with updates" icon={<Ship />} value={sc.helmWithUpdates} of={sc.helmReleases} unit="releases" pct={false} />
            </div>
          </div>

          {meta.warnings.length ? (
            <Alert variant="warning">
              <TriangleAlert />
              <AlertTitle>The collector reported {meta.warnings.length === 1 ? 'a problem' : `${meta.warnings.length} problems`}</AlertTitle>
              <AlertDescription>
                <ul className="mt-1 list-disc pl-4 text-xs" aria-label="Report warnings">
                  {meta.warnings.map((w) => (
                    <li key={w} className="break-all">
                      {w}
                    </li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          ) : null}

          <div className="grid gap-4 xl:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Report</CardTitle>
                <CardDescription>{meta.filename ?? 'provenance-latest.json'}</CardDescription>
                <CardAction>
                  <Button variant="ghost" size="sm" render={<Link to="/images" />}>
                    Images
                    <ArrowRight />
                  </Button>
                </CardAction>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-3">
                  <Meta label="Generated">{formatDateTime(meta.generatedAt)}</Meta>
                  <Meta label="Cluster">{meta.clusterName ?? '—'}</Meta>
                  <Meta label="Collector">{meta.collectorVersion || '—'}</Meta>
                  <Meta label="Schema">{meta.schemaVersion}</Meta>
                  <Meta label="Containers">{meta.totalImages}</Meta>
                  <Meta label="Unique images">{sc.unique}</Meta>
                </div>
                <div className="mt-4 flex flex-wrap gap-1" aria-label="Namespaces scanned">
                  {meta.namespacesScanned.map((ns) => (
                    <Badge key={ns} variant="outline" render={<Link to={`/images?namespace=${encodeURIComponent(ns)}`} />}>
                      {ns}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Recent reports</CardTitle>
                <CardDescription>One per collector run</CardDescription>
                <CardAction>
                  <Button variant="ghost" size="sm" render={<Link to="/reports" />}>
                    All reports
                    <ArrowRight />
                  </Button>
                </CardAction>
              </CardHeader>
              <CardContent>
                <ul className="flex flex-col divide-y text-sm" aria-label="Recent reports">
                  {(reports.data ?? []).slice(0, 5).map((r) => (
                    <li key={r.filename} className="flex items-center justify-between gap-3 py-2">
                      <span className="truncate font-mono text-xs" title={r.filename}>
                        {r.filename}
                      </span>
                      <span className="shrink-0 text-muted-foreground text-xs">
                        {r.summary?.uniqueImages ?? 0} images · {formatRelative(r.generatedAt)}
                      </span>
                    </li>
                  ))}
                  {reports.data && !reports.data.length ? <li className="py-2 text-muted-foreground">No timestamped reports yet.</li> : null}
                </ul>
              </CardContent>
            </Card>
          </div>
        </>
      ) : null}
    </>
  );
}
