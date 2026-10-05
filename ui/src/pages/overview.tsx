import { ArrowDownRight, ArrowRight, ArrowUpRight, Minus, ServerCrash, ShieldCheck, TriangleAlert } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts';
import { useControls, useFamilies, useScanners, useSettings, useSummary, useSupplyChain } from '@/api/queries';
import { PRODUCT_STIGS_HREF } from '@/components/product-stigs';
import { CatOpenChips, StigResultBar } from '@/components/stig';
import { coveragePct, SOURCE_LABEL } from '@/lib/stig';
import { ROLLUP_SERIES, ROLLUP_STATUS } from '@/components/family-rollup';
import type { Baseline } from '@/api/types';
import { applicableTotal, complianceTotals, totalsByStatus } from '@/lib/controls';
import { gradeForScore } from '@/lib/scoring';
import { clusterWeights, percent } from '@/lib/supply-chain';
import type { ScannerHealth, Severity, Summary, TrendPoint } from '@/api/types';
import { CardsSkeleton, ErrorAlert, PageHeader } from '@/components/page';
import { GradeBadge, GradeRing, PassFailBar, SCANNER_LABEL, SeverityBar, SeverityChips } from '@/components/posture';
import { ScanControl } from '@/components/scan-control';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { ageHours, formatAge, formatDateTime, formatRelative, formatScore, formatShortDate } from '@/lib/format';
import { trendDelta } from '@/lib/scoring';
import { SEVERITY_LABEL, severityFill, severityText } from '@/lib/severity-styles';
import { cn } from '@/lib/utils';

function Delta({ value }: { value: number | null }) {
  if (value === null) return <span className="text-muted-foreground text-xs">no previous scan</span>;
  const Icon = value > 0 ? ArrowUpRight : value < 0 ? ArrowDownRight : Minus;
  const tone = value > 0 ? 'text-success-foreground' : value < 0 ? 'text-destructive-foreground' : 'text-muted-foreground';
  return (
    <span className={cn('inline-flex items-center gap-0.5 font-medium text-sm tabular-nums', tone)}>
      <Icon className="size-4" aria-hidden="true" />
      {value > 0 ? '+' : ''}
      {value.toFixed(1)}
      <span className="ml-1 font-normal text-muted-foreground text-xs">vs previous scan</span>
    </span>
  );
}

function Stat({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="truncate text-muted-foreground text-xs">{label}</dt>
      <dd className="font-medium tabular-nums">{children}</dd>
    </div>
  );
}

function HeroTile({ summary }: { summary: Summary }) {
  const delta = trendDelta(summary.trend);
  const hasSc = summary.supplyChainScore !== null && summary.supplyChainScore !== undefined;
  const w = clusterWeights(hasSc);
  return (
    <Card className="motion-safe:animate-fade-in lg:col-span-2">
      <CardContent className="flex flex-col gap-5 sm:flex-row sm:items-center">
        <GradeRing score={summary.score} grade={summary.grade} size={148} stroke={12} />
        <div className="flex min-w-0 flex-1 flex-col gap-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-muted-foreground text-sm">Cluster security posture</p>
              <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span className="font-semibold text-4xl tabular-nums tracking-tight">{formatScore(summary.score)}</span>
                <span className="text-muted-foreground text-sm">/ 100 · grade {summary.grade}</span>
              </div>
              <Delta value={delta} />
            </div>
            <div className="w-full sm:w-60">
              <ScanControl lastScan={summary.lastScan} />
            </div>
          </div>
          <dl className={cn('grid grid-cols-2 gap-x-6 gap-y-3 text-sm', hasSc ? 'sm:grid-cols-3 2xl:grid-cols-5' : 'xl:grid-cols-4')}>
            <Stat label={`Vulnerability (×${w.vuln})`}>{formatScore(summary.vulnScore)}</Stat>
            <Stat label={`Configuration (×${w.posture})`}>{formatScore(summary.postureScore)}</Stat>
            {hasSc ? <Stat label={`Supply chain (×${w.supplyChain})`}>{formatScore(summary.supplyChainScore)}</Stat> : null}
            <Stat label="Images scored">
              {summary.images.scanned}/{summary.images.total}
              {summary.images.failed ? <span className="ml-1.5 font-normal text-destructive-foreground text-xs">{summary.images.failed} failed</span> : null}
            </Stat>
            <Stat label="Workloads · namespaces">
              {summary.workloads} · {summary.namespaces}
            </Stat>
          </dl>
          <p className="text-muted-foreground text-xs">
            Last scan {summary.lastScan ? `#${summary.lastScan.id} ${formatRelative(summary.lastScan.finishedAt ?? summary.lastScan.startedAt)}` : 'never'} · generated{' '}
            {formatDateTime(summary.generatedAt)}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

const TILE_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

function SeverityTiles({ summary }: { summary: Summary }) {
  return (
    <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
      {TILE_SEVERITIES.map((s) => (
        <Card key={s} size="sm" className="relative motion-safe:animate-slide-up-fade">
          <span className={cn('absolute inset-y-0 left-0 w-1', severityFill[s])} aria-hidden="true" />
          <CardContent className="flex flex-col gap-1 pl-5">
            <span className="text-muted-foreground text-xs uppercase tracking-wide">{SEVERITY_LABEL[s]}</span>
            <Link to={`/vulnerabilities?severity=${s}`} className="w-fit rounded-sm outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring">
              <span className={cn('font-semibold text-3xl tabular-nums', severityText[s])}>{summary.counts[s].toLocaleString()}</span>
            </Link>
            <span className="text-muted-foreground text-xs tabular-nums">
              {(summary.fixable[s] ?? 0).toLocaleString()} fixable
              {summary.slaOverdue?.[s] ? <span className="text-destructive-foreground"> · {summary.slaOverdue[s]} past SLA</span> : null}
            </span>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

const scannerLabel = (name: string) => (name === 'scap' ? 'OpenSCAP' : (SCANNER_LABEL[name as keyof typeof SCANNER_LABEL] ?? name));

function ScannerCard({ scanner }: { scanner: ScannerHealth }) {
  const age = ageHours(scanner.dbUpdatedAt);
  const scap = scanner.name === 'scap';
  // SCAP content is refreshed daily; benchmarks themselves change quarterly
  const stale = age !== null && age > (scap ? 24 * 8 : 72);
  return (
    <Card size="sm" data-testid={`scanner-${scanner.name}`}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {scannerLabel(scanner.name)}
          {scanner.version ? <span className="font-mono font-normal text-muted-foreground text-xs">v{scanner.version}</span> : null}
        </CardTitle>
        <CardAction>
          <Badge
            variant="secondary"
            className={cn('border', scanner.healthy ? 'border-success-foreground/40 bg-success text-success-foreground' : 'border-destructive-foreground/40 bg-destructive text-destructive-foreground')}
          >
            {scanner.healthy ? <ShieldCheck /> : <ServerCrash />}
            {scanner.healthy ? 'healthy' : 'error'}
          </Badge>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-1 text-sm">
        <span className={cn('tabular-nums', stale ? 'text-warning-foreground' : 'text-muted-foreground')}>
          {scap ? 'SCAP content fetched' : 'Vulnerability DB'} {formatAge(scanner.dbUpdatedAt)}
          {stale ? ' · stale' : ''}
        </span>
        {scap && scanner.contentVersions?.length ? (
          <ul className="flex flex-col gap-0.5 text-xs" aria-label="SCAP content versions">
            {scanner.contentVersions.map((c) => (
              <li key={`${c.name}-${c.version ?? ''}`} className="flex min-w-0 items-center gap-1.5">
                {c.source ? <span className="font-mono text-[10px] text-muted-foreground">{SOURCE_LABEL(c.source)}</span> : null}
                <span className="truncate" title={c.name}>{c.name}</span>
                {c.version ? <span className="ml-auto shrink-0 font-mono text-muted-foreground">{c.version}</span> : null}
              </li>
            ))}
          </ul>
        ) : null}
        {scanner.lastError ? <span className="line-clamp-2 text-destructive-foreground text-xs" title={scanner.lastError}>{scanner.lastError}</span> : null}
      </CardContent>
    </Card>
  );
}

/** §14 product/OS STIG tile (`summary.stig`); hidden when the API has no SCAP rollup. */
function StigTile({ summary }: { summary: Summary }) {
  const stig = summary.stig;
  if (!stig) return null;
  const cov = coveragePct(stig.coverage);
  return (
    <Card data-testid="stig-tile">
      <CardHeader>
        <CardTitle>Product STIGs</CardTitle>
        <CardDescription>OS and product STIGs evaluated inside images (OpenSCAP)</CardDescription>
        <CardAction>
          <Button variant="ghost" size="sm" render={<Link to={PRODUCT_STIGS_HREF} />}>
            Benchmarks
            <ArrowRight />
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap items-end gap-x-8 gap-y-3">
          <Link to={PRODUCT_STIGS_HREF} className="rounded-sm outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring" aria-label={`${stig.evaluated} images evaluated against a STIG benchmark`}>
            <span className="font-semibold text-3xl tabular-nums">{stig.evaluated}</span>
            <span className="ml-2 text-muted-foreground text-sm">images evaluated{cov !== null ? ` · ${cov.toFixed(0)}% coverage` : ''}</span>
          </Link>
          <div className="flex flex-col">
            <span className="text-muted-foreground text-xs">Open CAT I</span>
            <span className={cn('font-semibold text-3xl tabular-nums', stig.cat1Open ? 'text-destructive-foreground' : 'text-success-foreground')} data-testid="stig-cat1">
              {stig.cat1Open}
            </span>
          </div>
        </div>
        <StigResultBar counts={stig} legend={false} />
        <div className="flex flex-wrap items-center gap-2 text-muted-foreground text-xs tabular-nums">
          <CatOpenChips cat1={stig.cat1Open} cat2={stig.cat2Open} cat3={stig.cat3Open} />
          <span>
            {stig.pass.toLocaleString()} pass · {stig.fail.toLocaleString()} fail
            {stig.notApplicable ? ` · ${stig.notApplicable} images not applicable` : ''}
            {stig.errors ? ` · ${stig.errors} errors` : ''}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}

/** Summary scanners plus `scap` from `GET /scanners` when the summary doesn't carry it. */
function useScannerCards(summary: Summary): ScannerHealth[] {
  const hasScap = summary.scanners.some((s) => s.name === 'scap');
  const scanners = useScanners(!hasScap);
  const scap = hasScap ? undefined : scanners.data?.find((s) => s.name === 'scap' && s.enabled);
  return scap ? [...summary.scanners, scap] : summary.scanners;
}

function ScannerCards({ summary }: { summary: Summary }) {
  const cards = useScannerCards(summary);
  return (
    <div className={cn('grid gap-4', cards.length > 3 ? 'md:grid-cols-2 xl:grid-cols-4' : 'md:grid-cols-3')}>
      {cards.map((s) => (
        <ScannerCard key={s.name} scanner={s} />
      ))}
    </div>
  );
}

function MiniStat({ label, value, of }: { label: string; value: number; of: number }) {
  const p = percent(value, of);
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <span className="truncate text-muted-foreground text-xs">{label}</span>
      <span className="font-medium tabular-nums">{p === null ? '—' : `${p.toFixed(0)}%`}</span>
      <div className="h-1 overflow-hidden rounded-full bg-muted" aria-hidden="true">
        <div className="h-full rounded-full bg-primary" style={{ width: `${p ?? 0}%` }} />
      </div>
    </div>
  );
}

function SupplyChainTile() {
  const { data } = useSupplyChain();
  if (!data) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Supply chain</CardTitle>
        <CardDescription>
          {data.unique} images · {data.withUpdates} with updates · {data.helmWithUpdates}/{data.helmReleases} Helm releases behind
        </CardDescription>
        <CardAction>
          <Button variant="ghost" size="sm" render={<Link to="/supply-chain" />}>
            Details
            <ArrowRight />
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="flex items-center gap-5">
        <GradeRing score={data.score} grade={data.grade ?? gradeForScore(data.score)} size={88} stroke={8} />
        <div className="grid flex-1 grid-cols-2 gap-x-6 gap-y-3 text-sm">
          <MiniStat label="Signed" value={data.signed} of={data.unique} />
          <MiniStat label="Verified" value={data.verified} of={data.unique} />
          <MiniStat label="SBOM" value={data.withSbom} of={data.unique} />
          <MiniStat label="Provenance" value={data.withProvenance} of={data.unique} />
        </div>
      </CardContent>
    </Card>
  );
}

function ControlsTile() {
  const { data } = useControls();
  const families = useFamilies();
  const settings = useSettings();
  if (!data?.length || !data.some((c) => c.family || c.assertions || c.baseline)) return null;
  const baseline = (families.data?.baseline ?? settings.data?.controlsEngine?.baseline ?? 'moderate') as Baseline;
  // baseline numbers throughout (same as the Compliance tiles); full catalog in the title
  const totals = families.data?.totals ?? complianceTotals(data, baseline);
  const inB = totals.baseline;
  const counts = totalsByStatus(inB);
  const cov = { passing: inB.passing, total: applicableTotal(inB) };
  const cat = totals.catalog;
  const catalogTitle = `Full catalog (${cat.total} controls): ${cat.passing} passing · ${cat.hybrid} hybrid · ${cat.partial} partial · ${cat.failing} failing · ${cat.inherited} inherited · ${cat.orgProvided} organization-provided (unverified) · ${cat.notAssessed} not assessed`;
  return (
    <Card>
      <CardHeader>
        <CardTitle>NIST 800-53 controls</CardTitle>
        <CardDescription>Machine-collected evidence for an assessor, not an assessment result</CardDescription>
        <CardAction>
          <Button variant="ghost" size="sm" render={<Link to="/compliance" />}>
            Controls
            <ArrowRight />
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <Link to="/compliance" className="w-fit rounded-sm outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring" aria-label={`Controls with passing evidence ${cov.passing} of ${cov.total} (${baseline} baseline)`}>
          <span className="font-semibold text-3xl tabular-nums">{cov.passing}</span>
          <span className="text-muted-foreground text-lg tabular-nums">/{cov.total}</span>
          <span className="ml-2 text-muted-foreground text-sm">controls with passing evidence ({baseline} baseline)</span>
        </Link>
        <FamilyRollupBar counts={counts} />
        <p className="w-fit text-muted-foreground text-xs tabular-nums" title={catalogTitle}>
          {counts.hybrid} hybrid · {counts.partial} partial · {counts.failing} failing · {counts.inherited} inherited · {counts['not-assessed']} not assessed ({baseline} baseline)
        </p>
      </CardContent>
    </Card>
  );
}

function FamilyRollupBar({ counts }: { counts: Record<string, number> }) {
  const series = ROLLUP_SERIES.map((s) => ({ ...s, n: counts[ROLLUP_STATUS[s.key]] ?? 0 }));
  const total = series.reduce((a, s) => a + s.n, 0);
  if (!total) return null;
  return (
    <div className="flex h-2 gap-0.5 overflow-hidden rounded-full" role="img" aria-label={series.map((s) => `${s.n} ${s.label.toLowerCase()}`).join(', ')}>
      {series.map((s) => (s.n ? <span key={s.key} className="h-full" style={{ width: `${(s.n / total) * 100}%`, background: s.color }} title={`${s.n} ${s.label.toLowerCase()}`} /> : null))}
    </div>
  );
}

function TrendTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: TrendPoint }> }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="rounded-md border border-border bg-popover px-3 py-2 text-popover-foreground text-xs shadow-lg">
      <p className="font-medium">
        Scan #{p.scanId} · {formatDateTime(p.finishedAt)}
      </p>
      <p className="mt-1 flex items-center gap-2">
        <GradeBadge grade={p.grade} /> <span className="tabular-nums">score {formatScore(p.score)}</span>
      </p>
      <p className="mt-1 text-muted-foreground tabular-nums">
        {p.critical} critical · {p.high} high
      </p>
    </div>
  );
}

function TrendChart({ trend }: { trend: TrendPoint[] }) {
  if (trend.length < 2) {
    return <p className="py-12 text-center text-muted-foreground text-sm">Trend appears after two completed scans.</p>;
  }
  return (
    <div className="h-56 w-full" role="img" aria-label={`Score trend over the last ${trend.length} scans`}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={trend} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
          <defs>
            <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--chart-1)" stopOpacity={0.28} />
              <stop offset="100%" stopColor="var(--chart-1)" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--border)" strokeOpacity={0.5} strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="finishedAt"
            tickFormatter={(v: string) => formatShortDate(v)}
            tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: 'var(--border)' }}
            minTickGap={32}
          />
          <YAxis domain={[0, 100]} ticks={[0, 50, 65, 80, 90, 100]} tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }} tickLine={false} axisLine={false} />
          <ChartTooltip content={<TrendTooltip />} cursor={{ stroke: 'var(--border-strong)', strokeDasharray: '3 3' }} />
          <Area
            type="monotone"
            dataKey="score"
            stroke="var(--chart-1)"
            strokeWidth={2}
            fill="url(#trendFill)"
            connectNulls
            dot={false}
            activeDot={{ r: 4, stroke: 'var(--card)', strokeWidth: 2, fill: 'var(--chart-1)' }}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function TopRisks({ summary }: { summary: Summary }) {
  return (
    <Table aria-label="Top 10 riskiest images">
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="px-3">Image</TableHead>
          <TableHead className="px-3">Grade</TableHead>
          <TableHead className="px-3 text-right">Critical</TableHead>
          <TableHead className="px-3 text-right">High</TableHead>
          <TableHead className="px-3 text-right">Workloads</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {summary.topRisks.length === 0 ? (
          <TableRow>
            <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
              No scored images yet.
            </TableCell>
          </TableRow>
        ) : (
          summary.topRisks.map((r) => (
            <TableRow key={r.imageId}>
              <TableCell className="max-w-[200px] px-3 py-2">
                <Link to={`/images/${encodeURIComponent(r.imageId)}`} className="block truncate font-mono text-xs underline-offset-4 hover:underline" title={r.ref}>
                  {r.ref}
                </Link>
              </TableCell>
              <TableCell className="px-3 py-2">
                <GradeBadge grade={r.grade} score={r.score} />
              </TableCell>
              <TableCell className={cn('px-3 py-2 text-right tabular-nums', r.critical ? 'font-semibold text-destructive-foreground' : 'text-muted-foreground')}>{r.critical}</TableCell>
              <TableCell className={cn('px-3 py-2 text-right tabular-nums', r.high ? 'text-destructive-foreground' : 'text-muted-foreground')}>{r.high}</TableCell>
              <TableCell className="px-3 py-2 text-right tabular-nums">{r.workloads}</TableCell>
            </TableRow>
          ))
        )}
      </TableBody>
    </Table>
  );
}

export function OverviewPage() {
  const { data: summary, error, isLoading, refetch } = useSummary();

  return (
    <>
      <PageHeader title="Overview" description="Consensus of Trivy, Grype and Clair across every running container, plus Kubernetes configuration checks." />
      {error ? <ErrorAlert error={error} onRetry={() => void refetch()} /> : null}
      {isLoading ? <CardsSkeleton count={6} /> : null}
      {summary ? (
        <>
          {summary.warnings?.length ? (
            <Alert variant="warning">
              <TriangleAlert />
              <AlertTitle>Scanner warnings</AlertTitle>
              <AlertDescription>
                <ul className="list-disc pl-4">
                  {summary.warnings.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          ) : null}
          <div className="grid gap-4 lg:grid-cols-3">
            <HeroTile summary={summary} />
            <Card>
              <CardHeader>
                <CardTitle>Findings by severity</CardTitle>
                <CardDescription>Consensus findings in running images</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-3">
                <SeverityBar counts={summary.counts} />
                <SeverityChips counts={summary.counts} />
                <div className="mt-auto flex flex-col gap-1 border-border border-t pt-3">
                  <span className="text-muted-foreground text-xs">Posture checks</span>
                  <PassFailBar passed={summary.checks.passed} failed={summary.checks.failed} />
                  <Link to="/checks" className="w-fit text-muted-foreground text-xs underline-offset-4 hover:underline">
                    {summary.checks.failed.toLocaleString()} failing of {summary.checks.total.toLocaleString()} evaluations
                  </Link>
                </div>
              </CardContent>
            </Card>
          </div>

          <SeverityTiles summary={summary} />

          <div className="grid gap-4 xl:grid-cols-2 empty:hidden">
            <SupplyChainTile />
            <ControlsTile />
            <StigTile summary={summary} />
          </div>

          <ScannerCards summary={summary} />

          <div className="grid gap-4 xl:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Score trend</CardTitle>
                <CardDescription>Cluster score over the last {summary.trend.length} completed scans</CardDescription>
              </CardHeader>
              <CardContent>
                <TrendChart trend={summary.trend} />
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Riskiest images</CardTitle>
                <CardDescription>Lowest image vulnerability scores</CardDescription>
                <CardAction>
                  <Button variant="ghost" size="sm" render={<Link to="/images?sort=score&order=asc" />}>
                    All images
                    <ArrowRight />
                  </Button>
                </CardAction>
              </CardHeader>
              <CardContent>
                <TopRisks summary={summary} />
              </CardContent>
            </Card>
          </div>
        </>
      ) : null}
    </>
  );
}
