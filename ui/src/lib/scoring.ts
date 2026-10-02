import type { Grade, ScannerName, Severity, SeverityCounts } from '@/api/types';
import { SEVERITIES } from '@/api/types';

/** docs/SCORING.md grade thresholds. */
export function gradeForScore(score: number | null | undefined): Grade {
  if (score === null || score === undefined || Number.isNaN(score)) return '?';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  negligible: 1,
  unknown: 0,
};

export function severityRank(severity: Severity | null | undefined): number {
  return severity ? (SEVERITY_RANK[severity] ?? 0) : -1;
}

export function compareSeverity(a: Severity, b: Severity): number {
  return severityRank(b) - severityRank(a);
}

export function maxSeverity(values: Array<Severity | null | undefined>): Severity | null {
  let best: Severity | null = null;
  for (const value of values) {
    if (value && severityRank(value) > severityRank(best)) best = value;
  }
  return best;
}

/** Normalise any scanner spelling ("CRITICAL", "Negligible") to a Severity. */
export function normalizeSeverity(raw: string | null | undefined): Severity {
  const value = (raw ?? '').toLowerCase();
  return (SEVERITIES as readonly string[]).includes(value) ? (value as Severity) : 'unknown';
}

const GRADE_RANK: Record<Grade, number> = { A: 5, B: 4, C: 3, D: 2, F: 1, '?': 0 };
export function gradeRank(grade: Grade | null | undefined): number {
  return grade ? GRADE_RANK[grade] : -1;
}

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 10,
  high: 4,
  medium: 1,
  low: 0.2,
  negligible: 0.05,
  unknown: 0.05,
};

export function agreementMultiplier(scannersAgreeing: number, scannersSucceeded: number): number {
  if (scannersSucceeded <= 1) return 1;
  if (scannersAgreeing >= 3) return 1;
  if (scannersAgreeing === 2) return 0.85;
  return 0.6;
}

export interface ScoringFinding {
  severity: Severity;
  scanners: ScannerName[] | number;
  fixable: boolean;
}

/** imageVulnScore per SCORING.md: 100·exp(−penalty/40), 1 decimal. */
export function imageVulnScore(findings: ScoringFinding[], scannersSucceeded: number): number | null {
  if (scannersSucceeded <= 0) return null;
  let penalty = 0;
  for (const finding of findings) {
    const agreeing = typeof finding.scanners === 'number' ? finding.scanners : finding.scanners.length;
    penalty +=
      SEVERITY_WEIGHT[finding.severity] *
      agreementMultiplier(agreeing, scannersSucceeded) *
      (finding.fixable ? 1.25 : 1);
  }
  return Math.round(100 * Math.exp(-penalty / 40) * 10) / 10;
}

export function postureScore(failedWeights: number[]): number {
  const sum = failedWeights.reduce((a, b) => a + b, 0);
  return Math.round(100 * Math.exp(-sum / 20) * 10) / 10;
}

export function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0 };
}

export function totalCount(counts: Partial<SeverityCounts> | null | undefined): number {
  if (!counts) return 0;
  return SEVERITIES.reduce((sum, s) => sum + (counts[s] ?? 0), 0);
}

/** Score delta vs the previous completed scan in a trend series (oldest → newest). */
export function trendDelta(trend: Array<{ score: number | null }>): number | null {
  const scored = trend.filter((p) => p.score !== null && p.score !== undefined);
  if (scored.length < 2) return null;
  const last = scored[scored.length - 1].score as number;
  const prev = scored[scored.length - 2].score as number;
  return Math.round((last - prev) * 10) / 10;
}
