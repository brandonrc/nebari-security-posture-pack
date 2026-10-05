/**
 * §14 SCAP / product-STIG helpers: tolerant spellings (OpenSCAP, DISA and the API may say
 * `high`/`CAT I`/`cat1`, `notapplicable`/`not_applicable`), labels and tones.
 */
import type { Grade, ImageStigBrief, ImageSummary, ScapCat, ScapResult } from '@/api/types';
import { gradeForScore } from '@/lib/scoring';

export function normCat(value: unknown): ScapCat {
  const v = String(value ?? '').trim().toLowerCase().replace(/^cat\s*/, '').replace(/[\s_-]/g, '');
  if (v === '1' || v === 'i' || v === 'high' || v === 'critical') return 'cat1';
  if (v === '3' || v === 'iii' || v === 'low') return 'cat3';
  return 'cat2';
}

export const CAT_LABEL: Record<ScapCat, string> = { cat1: 'CAT I', cat2: 'CAT II', cat3: 'CAT III' };

export const CAT_TONE: Record<ScapCat, string> = {
  cat1: 'border-destructive-foreground bg-destructive-foreground text-canvas',
  cat2: 'border-destructive-foreground/40 bg-destructive text-destructive-foreground',
  cat3: 'border-warning-foreground/40 bg-warning text-warning-foreground',
};

export function normResult(value: unknown): ScapResult {
  const v = String(value ?? '').trim().toLowerCase().replace(/[\s_-]/g, '');
  switch (v) {
    case 'pass':
    case 'fixed':
      return 'pass';
    case 'fail':
      return 'fail';
    case 'notapplicable':
    case 'na':
      return 'notapplicable';
    case 'notchecked':
    case 'notselected':
      return 'notchecked';
    case 'error':
      return 'error';
    case 'informational':
      return 'informational';
    default:
      return 'unknown';
  }
}

export const RESULT_LABEL: Record<ScapResult, string> = {
  pass: 'Pass',
  fail: 'Fail',
  notapplicable: 'Not applicable',
  notchecked: 'Not checked',
  error: 'Error',
  unknown: 'Unknown',
  informational: 'Informational',
};

export const RESULT_TONE: Record<ScapResult, string> = {
  pass: 'border-success-foreground/40 bg-success text-success-foreground',
  fail: 'border-destructive-foreground/40 bg-destructive text-destructive-foreground',
  notapplicable: 'border-border bg-muted text-muted-foreground-strong',
  notchecked: 'border-dashed border-border-strong bg-transparent text-muted-foreground-strong',
  error: 'border-warning-foreground/40 bg-warning text-warning-foreground',
  unknown: 'border-dashed border-border-strong bg-transparent text-muted-foreground-strong',
  informational: 'border-info-foreground/40 bg-info text-info-foreground',
};

/** Bar segment fills, in display order. */
export const RESULT_SEGMENTS: Array<{ key: 'pass' | 'fail' | 'notapplicable' | 'notchecked' | 'error'; label: string; fill: string }> = [
  { key: 'pass', label: 'pass', fill: 'bg-success-foreground' },
  { key: 'fail', label: 'fail', fill: 'bg-destructive-foreground' },
  { key: 'error', label: 'error', fill: 'bg-warning-foreground' },
  { key: 'notapplicable', label: 'not applicable', fill: 'bg-muted-foreground/40' },
  { key: 'notchecked', label: 'not checked', fill: 'bg-border-strong' },
];

export const SOURCE_LABEL = (source: string | null | undefined) => {
  const s = String(source ?? '').toLowerCase();
  return s === 'disa' ? 'DISA' : s === 'ssg' ? 'SSG' : s ? s.toUpperCase() : '—';
};

/** `coverage` may be a fraction (0–1) or a percentage. */
export function coveragePct(value: number | null | undefined): number | null {
  if (value === null || value === undefined || !Number.isFinite(value)) return null;
  return value <= 1 ? value * 100 : Math.min(100, value);
}

/** Pass rate over evaluated (pass + fail) rules, as a percentage. */
export function passRate(pass: number, fail: number): number | null {
  return pass + fail > 0 ? (pass / (pass + fail)) * 100 : null;
}

export function stigGrade(score: number | null | undefined): Grade {
  return gradeForScore(score ?? null);
}

/** `image.stig`: undefined = API without §14; null = no applicable benchmark. */
export function imageStigScore(image: Pick<ImageSummary, 'stig'>): number | null | undefined {
  if (image.stig === undefined) return undefined;
  if (image.stig === null || typeof image.stig !== 'object') return null;
  return typeof image.stig.score === 'number' ? image.stig.score : null;
}

/**
 * Image-level STIG state (`image.stig`): `undefined` = API without §14; `null` = never evaluated
 * (the API serves `stig: null` until the SCAP stage stores a result). `unscored` = evaluated, but
 * no rule was pass/fail (e.g. a manual-only checklist).
 */
export type StigState = 'evaluated' | 'unscored' | 'notEvaluated' | 'notApplicable' | 'noContent' | 'error' | 'timeout';

export function stigState(stig: ImageStigBrief | null | undefined): StigState | undefined {
  if (stig === undefined) return undefined;
  if (stig === null || typeof stig !== 'object') return 'notEvaluated';
  const status = String(stig.status ?? '');
  const scored = typeof stig.score === 'number';
  if (status === 'evaluated' || (!status && scored)) return scored ? 'evaluated' : 'unscored';
  if (status === 'notApplicable' || status === 'noContent' || status === 'error' || status === 'timeout') return status;
  return 'notEvaluated';
}

/** Short cell labels for the states without a score. */
export const STIG_STATE_LABEL: Record<Exclude<StigState, 'evaluated'>, string> = {
  unscored: 'not scored',
  notEvaluated: 'not yet',
  notApplicable: 'n/a',
  noContent: 'no content',
  error: 'error',
  timeout: 'timeout',
};

/** Tooltip for a state (plus the API's reason / error when it has one). */
export function stigStateTooltip(state: StigState, stig?: ImageStigBrief | null): string {
  const why = stig?.error ? ` (${stig.error})` : '';
  switch (state) {
    case 'evaluated':
      return stig?.stale ? `Previous STIG result: the last re-evaluation failed${stig.staleError ? ` (${stig.staleError})` : ''}; the next scan retries it` : 'Open the STIG tab';
    case 'unscored':
      return 'Evaluated, but no rule passed or failed (e.g. manual checks only), so there is no score';
    case 'notEvaluated':
      return 'Not evaluated yet: the SCAP stage has not evaluated this image (it runs after a scan while the SCAP scanner is enabled)';
    case 'notApplicable':
      return `Not applicable: no SCAP benchmark applies to this image’s OS or products${why}`;
    case 'noContent':
      return `No content: a benchmark applies, but its SCAP content is not on the content volume${why}`;
    case 'timeout':
      return `SCAP evaluation timed out${why}`;
    default:
      return `SCAP evaluation failed${why}`;
  }
}

/** OpenSCAP rootfs extraction fidelity: anything but full/ok is shown as degraded. */
export function fidelityDegraded(value: string | null | undefined): boolean {
  if (!value) return false;
  return !['full', 'ok', 'complete', 'exact'].includes(value.toLowerCase());
}
