import type { Grade, Severity } from '@/api/types';

/**
 * DESIGN §7 colour mapping — semantic Nebari tokens only, so light/dark flip
 * automatically. "strong" = solid fill using the feedback foreground token;
 * "soft" = the feedback background token with its foreground text.
 */
export const severityClass: Record<Severity, string> = {
  critical: 'border-destructive-foreground bg-destructive-foreground text-canvas',
  high: 'border-destructive-foreground/40 bg-destructive text-destructive-foreground',
  medium: 'border-warning-foreground/30 bg-warning text-warning-foreground',
  low: 'border-info-foreground/30 bg-info text-info-foreground',
  negligible: 'border-border bg-muted text-muted-foreground-strong',
  unknown: 'border-border bg-muted text-muted-foreground-strong',
};

/** Text-only tone for numbers/icons. */
export const severityText: Record<Severity, string> = {
  critical: 'text-destructive-foreground',
  high: 'text-destructive-foreground',
  medium: 'text-warning-foreground',
  low: 'text-info-foreground',
  negligible: 'text-muted-foreground',
  unknown: 'text-muted-foreground',
};

/** Fill class for bars / dots. */
export const severityFill: Record<Severity, string> = {
  critical: 'bg-destructive-foreground',
  high: 'bg-destructive-foreground/60',
  medium: 'bg-warning-foreground',
  low: 'bg-info-foreground',
  negligible: 'bg-muted-foreground',
  unknown: 'bg-muted-foreground',
};

export const gradeClass: Record<Grade, string> = {
  A: 'border-success-foreground bg-success-foreground text-canvas',
  B: 'border-success-foreground/40 bg-success text-success-foreground',
  C: 'border-warning-foreground/40 bg-warning text-warning-foreground',
  D: 'border-destructive-foreground/40 bg-destructive text-destructive-foreground',
  F: 'border-destructive-foreground bg-destructive-foreground text-canvas',
  '?': 'border-border bg-muted text-muted-foreground-strong',
};

/** CSS colour (token var) for SVG strokes, e.g. the grade ring. */
export const gradeStroke: Record<Grade, string> = {
  A: 'var(--success-foreground)',
  B: 'var(--success-foreground)',
  C: 'var(--warning-foreground)',
  D: 'var(--destructive-foreground)',
  F: 'var(--destructive-foreground)',
  '?': 'var(--muted-foreground)',
};

export const gradeText: Record<Grade, string> = {
  A: 'text-success-foreground',
  B: 'text-success-foreground',
  C: 'text-warning-foreground',
  D: 'text-destructive-foreground',
  F: 'text-destructive-foreground',
  '?': 'text-muted-foreground',
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  negligible: 'Negligible',
  unknown: 'Unknown',
};
