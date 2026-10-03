import { CircleAlert, CircleCheck, CircleMinus, CircleSlash, Clock } from 'lucide-react';
import type { ReactNode } from 'react';
import type { Grade, ScannerName, ScannerRunStatus, ScannerRunSummary, Severity, SeverityCounts } from '@/api/types';
import { SCANNERS } from '@/api/types';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { formatDuration, formatScore } from '@/lib/format';
import { gradeClass, gradeStroke, SEVERITY_LABEL, severityClass, severityFill } from '@/lib/severity-styles';
import { cn } from '@/lib/utils';

export const SCANNER_LABEL: Record<ScannerName, string> = { trivy: 'Trivy', grype: 'Grype', clair: 'Clair' };

export function GradeBadge({ grade, score, className }: { grade: Grade | null | undefined; score?: number | null; className?: string }) {
  const g: Grade = grade ?? '?';
  return (
    <span className={cn('inline-flex items-center gap-1.5', className)}>
      <Badge
        variant="secondary"
        aria-label={`Grade ${g}`}
        className={cn('h-6 min-w-6 justify-center rounded-md border px-1.5 font-semibold text-sm tabular-nums', gradeClass[g])}
      >
        {g}
      </Badge>
      {score !== undefined ? <span className="text-muted-foreground text-xs tabular-nums">{formatScore(score)}</span> : null}
    </span>
  );
}

export function SeverityBadge({ severity, className, children }: { severity: Severity; className?: string; children?: ReactNode }) {
  return (
    <Badge variant="secondary" className={cn('border capitalize', severityClass[severity], className)}>
      {children ?? SEVERITY_LABEL[severity]}
    </Badge>
  );
}

const CHIP_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];
const CHIP_ABBR: Record<Severity, string> = { critical: 'C', high: 'H', medium: 'M', low: 'L', negligible: 'N', unknown: 'U' };

/** Compact consensus severity counts, e.g. [C 3][H 12][M 4][L 1]. Zero counts are dimmed. */
export function SeverityChips({ counts, className }: { counts: Partial<SeverityCounts>; className?: string }) {
  return (
    <span className={cn('inline-flex flex-nowrap items-center gap-1', className)}>
      {CHIP_ORDER.map((s) => {
        const n = counts[s] ?? 0;
        return (
          <span
            key={s}
            title={`${n} ${SEVERITY_LABEL[s].toLowerCase()}`}
            aria-label={`${n} ${SEVERITY_LABEL[s].toLowerCase()}`}
            className={cn(
              'inline-flex h-5 min-w-7 items-center justify-between gap-0.5 rounded-sm border px-1 font-mono text-[11px] tabular-nums leading-none',
              n > 0 ? severityClass[s] : 'border-border/60 bg-transparent text-muted-foreground/70',
            )}
          >
            <span className="font-semibold">{CHIP_ABBR[s]}</span>
            <span>{n}</span>
          </span>
        );
      })}
    </span>
  );
}

const STATUS_META: Record<ScannerRunStatus, { icon: typeof CircleCheck; tone: string; label: string }> = {
  ok: { icon: CircleCheck, tone: 'text-success-foreground', label: 'ok' },
  error: { icon: CircleAlert, tone: 'text-destructive-foreground', label: 'error' },
  timeout: { icon: Clock, tone: 'text-warning-foreground', label: 'timeout' },
  unsupported: { icon: CircleSlash, tone: 'text-muted-foreground', label: 'unsupported' },
  skipped: { icon: CircleMinus, tone: 'text-muted-foreground', label: 'skipped' },
};

export function ScannerStatusIcon({ status, className }: { status: ScannerRunStatus; className?: string }) {
  const meta = STATUS_META[status] ?? STATUS_META.skipped;
  const Icon = meta.icon;
  return <Icon aria-hidden="true" className={cn('size-4', meta.tone, className)} />;
}

export function scannerStatusLabel(status: ScannerRunStatus): string {
  return (STATUS_META[status] ?? STATUS_META.skipped).label;
}

/** Per-scanner mini status (✓ / ! / –) with a tooltip carrying the details. */
export function ScannerGlyphs({ scanners }: { scanners: Partial<Record<ScannerName, ScannerRunSummary>> }) {
  return (
    <span className="inline-flex items-center gap-1">
      {SCANNERS.map((name) => {
        const run = scanners[name];
        const status: ScannerRunStatus = run?.status ?? 'skipped';
        return (
          <Tooltip key={name}>
            <TooltipTrigger
              render={<span />}
              aria-label={`${SCANNER_LABEL[name]}: ${scannerStatusLabel(status)}`}
              className="inline-flex cursor-default items-center rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
              tabIndex={0}
            >
              <ScannerStatusIcon status={status} />
            </TooltipTrigger>
            <TooltipContent className="max-w-72">
              <p className="font-medium">
                {SCANNER_LABEL[name]} · {scannerStatusLabel(status)}
              </p>
              {run ? (
                <p className="text-xs opacity-80">
                  {run.findings} findings · {formatDuration(run.durationMs)}
                  {run.version ? ` · v${run.version}` : ''}
                </p>
              ) : null}
              {run?.error ? <p className="mt-1 text-xs opacity-90">{run.error}</p> : null}
            </TooltipContent>
          </Tooltip>
        );
      })}
    </span>
  );
}

/** Agreement index (0–1) as three dots: how many of three scanners agree on average. */
export function AgreementDots({ value, className }: { value: number | null | undefined; className?: string }) {
  if (value === null || value === undefined) return <span className="text-muted-foreground">—</span>;
  const filled = Math.max(0, Math.min(3, Math.round(value * 3)));
  return (
    <span className={cn('inline-flex items-center gap-1', className)} title={`Agreement ${Math.round(value * 100)}%`} aria-label={`Agreement ${Math.round(value * 100)}%`}>
      {[0, 1, 2].map((i) => (
        <span key={i} className={cn('size-2 rounded-full', i < filled ? 'bg-primary' : 'border border-border-strong bg-transparent')} />
      ))}
      <span className="ml-1 text-muted-foreground text-xs tabular-nums">{Math.round(value * 100)}%</span>
    </span>
  );
}

/** SVG score ring 0–100 coloured by grade. */
export function GradeRing({ score, grade, size = 120, stroke = 10, label = true }: { score: number | null | undefined; grade: Grade; size?: number; stroke?: number; label?: boolean }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const pct = score === null || score === undefined ? 0 : Math.max(0, Math.min(100, score)) / 100;
  return (
    <div className="relative inline-flex shrink-0 items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Score ${formatScore(score)} of 100, grade ${grade}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--muted)" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={gradeStroke[grade]}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${c * pct} ${c}`}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          className="motion-safe:transition-[stroke-dasharray] motion-safe:duration-(--duration-slow)"
        />
      </svg>
      {label ? (
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-semibold leading-none tracking-tight" style={{ fontSize: size * 0.36 }}>
            {grade}
          </span>
          <span className="mt-1 text-muted-foreground tabular-nums" style={{ fontSize: Math.max(11, size * 0.11) }}>
            {formatScore(score)}
          </span>
        </div>
      ) : null}
    </div>
  );
}

/** Horizontal pass/fail bar with counts. */
export function PassFailBar({ passed, failed, className, showLabel = true }: { passed: number; failed: number; className?: string; showLabel?: boolean }) {
  const total = passed + failed;
  const pct = total ? (passed / total) * 100 : 0;
  return (
    <div className={cn('flex min-w-28 items-center gap-2', className)}>
      <div
        className="flex h-2 flex-1 gap-0.5 overflow-hidden rounded-full"
        role="img"
        aria-label={`${passed} passed, ${failed} failed`}
      >
        {total === 0 ? (
          <span className="h-full w-full bg-muted" />
        ) : (
          <>
            {passed > 0 ? <span className="h-full rounded-l-full bg-success-foreground" style={{ width: `${pct}%` }} /> : null}
            {failed > 0 ? <span className="h-full flex-1 rounded-r-full bg-destructive-foreground" /> : null}
          </>
        )}
      </div>
      {showLabel ? (
        <span className="whitespace-nowrap text-muted-foreground text-xs tabular-nums">
          <span className="text-success-foreground">{passed}</span> / <span className="text-destructive-foreground">{failed}</span>
        </span>
      ) : null}
    </div>
  );
}

/** NIST 800-53 control chips (§11). */
export function ControlChips({ controls, max = 3 }: { controls?: string[] | null; max?: number }) {
  if (!controls?.length) return <span className="text-muted-foreground">—</span>;
  const shown = controls.slice(0, max);
  const rest = controls.length - shown.length;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {shown.map((c) => (
        <Badge key={c} variant="outline" className="font-mono text-[10px]">
          {c}
        </Badge>
      ))}
      {rest > 0 ? (
        <Badge variant="ghost" className="text-[10px] text-muted-foreground" title={controls.slice(max).join(', ')}>
          +{rest}
        </Badge>
      ) : null}
    </span>
  );
}

const STATUS_TONE: Record<string, string> = {
  done: 'border-success-foreground/40 bg-success text-success-foreground',
  ok: 'border-success-foreground/40 bg-success text-success-foreground',
  running: 'border-info-foreground/40 bg-info text-info-foreground',
  queued: 'border-border bg-muted text-muted-foreground-strong',
  failed: 'border-destructive-foreground/40 bg-destructive text-destructive-foreground',
  error: 'border-destructive-foreground/40 bg-destructive text-destructive-foreground',
  cancelled: 'border-warning-foreground/40 bg-warning text-warning-foreground',
  timeout: 'border-warning-foreground/40 bg-warning text-warning-foreground',
  Open: 'border-destructive-foreground/40 bg-destructive text-destructive-foreground',
  NotAFinding: 'border-success-foreground/40 bg-success text-success-foreground',
  Not_Reviewed: 'border-border bg-muted text-muted-foreground-strong',
  satisfied: 'border-success-foreground/40 bg-success text-success-foreground',
  'not-satisfied': 'border-destructive-foreground/40 bg-destructive text-destructive-foreground',
  pass: 'border-success-foreground/40 bg-success text-success-foreground',
  fail: 'border-destructive-foreground/40 bg-destructive text-destructive-foreground',
  // §13 control / assertion statuses
  implemented: 'border-success-foreground/40 bg-success text-success-foreground',
  partial: 'border-warning-foreground/40 bg-warning text-warning-foreground',
  'not-implemented': 'border-destructive-foreground/40 bg-destructive text-destructive-foreground',
  inherited: 'border-info-foreground/40 bg-info text-info-foreground',
  'not-applicable': 'border-border bg-muted text-muted-foreground-strong',
  unknown: 'border-dashed border-border-strong bg-transparent text-muted-foreground-strong',
  // Helm release statuses
  deployed: 'border-success-foreground/40 bg-success text-success-foreground',
  'pending-upgrade': 'border-info-foreground/40 bg-info text-info-foreground',
  'pending-install': 'border-info-foreground/40 bg-info text-info-foreground',
  superseded: 'border-border bg-muted text-muted-foreground-strong',
};

const STATUS_TEXT: Record<string, string> = {
  NotAFinding: 'Not a finding',
  Not_Reviewed: 'Not reviewed',
  'not-satisfied': 'Not satisfied',
  'not-implemented': 'Not implemented',
  'not-applicable': 'Not applicable',
  'pending-upgrade': 'Pending upgrade',
  'pending-install': 'Pending install',
};

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  return (
    <Badge variant="secondary" className={cn('border capitalize', STATUS_TONE[status] ?? 'border-border bg-muted text-muted-foreground-strong', className)}>
      {status === 'running' ? <span className="size-1.5 rounded-full bg-current motion-safe:animate-skeleton-pulse" aria-hidden="true" /> : null}
      {STATUS_TEXT[status] ?? status}
    </Badge>
  );
}

const BASELINE_TONE: Record<string, string> = {
  low: 'border-border-strong bg-background text-foreground',
  moderate: 'border-info-foreground/40 bg-info text-info-foreground',
  high: 'border-chart-1/50 bg-transparent text-foreground',
};

/** NIST baseline chip: lowest baseline a control belongs to (L / M / H). */
export function BaselineBadge({ baseline }: { baseline: string | null | undefined }) {
  if (!baseline) return <Badge variant="ghost" className="text-[11px] text-muted-foreground">none</Badge>;
  return (
    <Badge variant="secondary" className={cn('border text-[11px] capitalize', BASELINE_TONE[baseline] ?? BASELINE_TONE.low)} title={`In the ${baseline} baseline and above`}>
      {baseline}
    </Badge>
  );
}

/** Stacked severity distribution bar (used in tiles/legends). */
export function SeverityBar({ counts }: { counts: Partial<SeverityCounts> }) {
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'negligible'];
  const total = order.reduce((a, s) => a + (counts[s] ?? 0), 0);
  if (!total) return <div className="h-2 rounded-full bg-muted" />;
  return (
    <div className="flex h-2 gap-0.5 overflow-hidden rounded-full" role="img" aria-label={order.map((s) => `${counts[s] ?? 0} ${s}`).join(', ')}>
      {order.map((s) =>
        counts[s] ? <span key={s} className={cn('h-full', severityFill[s])} style={{ width: `${((counts[s] ?? 0) / total) * 100}%` }} /> : null,
      )}
    </div>
  );
}
