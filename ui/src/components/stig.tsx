import type { ImageStigBrief, ScapCat } from '@/api/types';
import { GradeBadge } from '@/components/posture';
import { Badge } from '@/components/ui/badge';
import { CAT_LABEL, CAT_TONE, normCat, normResult, RESULT_LABEL, RESULT_SEGMENTS, RESULT_TONE, SOURCE_LABEL, STIG_STATE_LABEL, stigGrade, stigState, stigStateTooltip } from '@/lib/stig';
import { cn } from '@/lib/utils';

/** §14 shared bits: CAT / result / source badges, the results bar and open-CAT chips. */

export function CatBadge({ cat, className }: { cat: ScapCat | string; className?: string }) {
  const c = normCat(cat);
  return (
    <Badge variant="secondary" className={cn('border font-mono', CAT_TONE[c], className)}>
      {CAT_LABEL[c]}
    </Badge>
  );
}

export function ResultBadge({ result }: { result: string }) {
  const r = normResult(result);
  return (
    <Badge variant="secondary" className={cn('border', RESULT_TONE[r])}>
      {RESULT_LABEL[r]}
    </Badge>
  );
}

export function SourceBadge({ source }: { source: string | null | undefined }) {
  const label = SOURCE_LABEL(source);
  return (
    <Badge
      variant="outline"
      className={cn('font-mono', label === 'DISA' && 'border-info-foreground/40 bg-info text-info-foreground')}
      title={label === 'DISA' ? 'DISA SCAP benchmark (authoritative)' : label === 'SSG' ? 'ComplianceAsCode / SCAP Security Guide' : undefined}
    >
      {label}
    </Badge>
  );
}

type Counts = { pass: number; fail: number; notapplicable?: number; notchecked?: number; error?: number };

/** Stacked pass / fail / error / not applicable / not checked bar with a legend. */
export function StigResultBar({ counts, legend = true, className }: { counts: Counts; legend?: boolean; className?: string }) {
  const segs = RESULT_SEGMENTS.map((s) => ({ ...s, n: counts[s.key] ?? 0 }));
  const total = segs.reduce((a, s) => a + s.n, 0);
  const label = segs.map((s) => `${s.n} ${s.label}`).join(', ');
  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      <div className="flex h-2 gap-0.5 overflow-hidden rounded-full bg-muted" role="img" aria-label={label}>
        {total ? segs.map((s) => (s.n ? <span key={s.key} className={cn('h-full', s.fill)} style={{ width: `${(s.n / total) * 100}%` }} title={`${s.n} ${s.label}`} /> : null)) : null}
      </div>
      {legend ? (
        <div className="flex flex-wrap gap-x-3 gap-y-1 text-muted-foreground text-xs tabular-nums">
          {segs.map((s) =>
            s.n || s.key !== 'error' ? (
              <span key={s.key} className="inline-flex items-center gap-1">
                <span className={cn('size-2 rounded-sm', s.fill)} aria-hidden="true" />
                {s.n} {s.label}
              </span>
            ) : null,
          )}
        </div>
      ) : null}
    </div>
  );
}

/** Open (failed) rule counts per CAT; `undefined` counts render as "—". */
export function CatOpenChips({ cat1, cat2, cat3, className }: { cat1?: number; cat2?: number; cat3?: number; className?: string }) {
  const items: Array<[ScapCat, number | undefined]> = [
    ['cat1', cat1],
    ['cat2', cat2],
    ['cat3', cat3],
  ];
  return (
    <span className={cn('inline-flex flex-wrap gap-1.5', className)}>
      {items.map(([c, n]) => (
        <Badge
          key={c}
          variant="secondary"
          className={cn('border font-mono tabular-nums', n ? CAT_TONE[c] : 'border-border bg-muted text-muted-foreground-strong')}
          aria-label={`${CAT_LABEL[c]} open: ${n ?? 'unknown'}`}
        >
          {CAT_LABEL[c]} · {n ?? '—'}
        </Badge>
      ))}
    </span>
  );
}

/**
 * Image STIG state: the grade-coloured score (with a "stale" marker when the last re-evaluation
 * failed), or a label that tells "not yet" (never evaluated), "n/a" (no applicable benchmark),
 * "no content", "not scored", "error" and "timeout" apart, each with a tooltip.
 */
export function StigStateLabel({ stig }: { stig: ImageStigBrief | null | undefined }) {
  const state = stigState(stig);
  if (state === undefined) return null;
  const title = stigStateTooltip(state, stig);
  if (state === 'evaluated') {
    return (
      <span className="inline-flex items-center gap-1" title={title}>
        <GradeBadge grade={stigGrade(stig?.score ?? null)} score={stig?.score ?? null} />
        {stig?.stale ? (
          <Badge variant="outline" className="border-warning-foreground/40 text-warning-foreground" data-testid="stig-stale">
            stale
          </Badge>
        ) : null}
      </span>
    );
  }
  const warn = state === 'error' || state === 'timeout';
  return (
    <span className={cn('text-xs', warn ? 'text-warning-foreground' : 'text-muted-foreground', state === 'notEvaluated' && 'italic')} title={title} data-stig-state={state}>
      {STIG_STATE_LABEL[state]}
    </span>
  );
}

/** STIG score cell: grade-coloured score, or "n/a" (no applicable benchmark). */
export function StigScore({ score }: { score: number | null | undefined }) {
  if (score === null || score === undefined) {
    return (
      <span className="text-muted-foreground text-xs" title="No applicable SCAP benchmark">
        n/a
      </span>
    );
  }
  return <GradeBadge grade={stigGrade(score)} score={score} />;
}
