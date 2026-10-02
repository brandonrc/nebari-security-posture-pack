import { describe, expect, it } from 'vitest';
import {
  agreementMultiplier,
  compareSeverity,
  gradeForScore,
  imageVulnScore,
  maxSeverity,
  normalizeSeverity,
  postureScore,
  totalCount,
  trendDelta,
} from './scoring';
import { severityClass, gradeClass } from './severity-styles';
import { formatAge, formatBytes, formatDuration, formatRelative, shortDigest } from './format';

describe('gradeForScore', () => {
  it('maps SCORING.md thresholds', () => {
    expect(gradeForScore(100)).toBe('A');
    expect(gradeForScore(90)).toBe('A');
    expect(gradeForScore(89.9)).toBe('B');
    expect(gradeForScore(80)).toBe('B');
    expect(gradeForScore(65)).toBe('C');
    expect(gradeForScore(64.9)).toBe('D');
    expect(gradeForScore(50)).toBe('D');
    expect(gradeForScore(49.9)).toBe('F');
    expect(gradeForScore(0)).toBe('F');
    expect(gradeForScore(null)).toBe('?');
  });
});

describe('imageVulnScore', () => {
  it('reproduces the SCORING.md worked examples', () => {
    expect(imageVulnScore([{ severity: 'critical', scanners: 3, fixable: true }], 3)).toBe(73.2);
    expect(imageVulnScore(Array.from({ length: 5 }, () => ({ severity: 'high' as const, scanners: 3, fixable: false })), 3)).toBe(60.7);
    expect(imageVulnScore(Array.from({ length: 30 }, () => ({ severity: 'medium' as const, scanners: 3, fixable: false })), 3)).toBe(47.2);
    expect(imageVulnScore([], 3)).toBe(100);
  });

  it('returns null when no scanner succeeded', () => {
    expect(imageVulnScore([], 0)).toBeNull();
  });

  it('applies agreement multipliers', () => {
    expect(agreementMultiplier(1, 3)).toBe(0.6);
    expect(agreementMultiplier(2, 3)).toBe(0.85);
    expect(agreementMultiplier(3, 3)).toBe(1);
    expect(agreementMultiplier(1, 1)).toBe(1);
  });
});

describe('severity helpers', () => {
  it('orders and normalises severities', () => {
    expect(maxSeverity(['low', 'critical', 'high'])).toBe('critical');
    expect(maxSeverity([undefined, null])).toBeNull();
    expect(['low', 'critical', 'medium'].sort((a, b) => compareSeverity(a as never, b as never))).toEqual([
      'critical',
      'medium',
      'low',
    ]);
    expect(normalizeSeverity('CRITICAL')).toBe('critical');
    expect(normalizeSeverity('Negligible')).toBe('negligible');
    expect(normalizeSeverity('weird')).toBe('unknown');
  });

  it('uses only semantic tokens for colour', () => {
    const all = [...Object.values(severityClass), ...Object.values(gradeClass)].join(' ');
    expect(all).not.toMatch(/#[0-9a-f]{3,6}|red-|green-|yellow-|blue-/i);
    expect(severityClass.critical).toContain('destructive');
    expect(severityClass.medium).toContain('warning');
    expect(severityClass.low).toContain('info');
    expect(gradeClass.A).toContain('success');
  });

  it('sums counts and computes trend delta', () => {
    expect(totalCount({ critical: 1, high: 2, medium: 3 })).toBe(6);
    expect(trendDelta([{ score: 70 }, { score: null }, { score: 72.5 }])).toBe(2.5);
    expect(trendDelta([{ score: 70 }])).toBeNull();
  });

  it('computes posture score', () => {
    expect(postureScore([])).toBe(100);
    expect(postureScore([10, 4])).toBe(49.7);
  });
});

describe('format helpers', () => {
  const now = Date.parse('2026-10-02T12:00:00Z');
  it('formats relative times and ages', () => {
    expect(formatRelative('2026-10-02T09:00:00Z', now)).toBe('3h ago');
    expect(formatRelative(null, now)).toBe('—');
    expect(formatAge('2026-09-27T12:00:00Z', now)).toBe('5 days old');
    expect(formatAge('2026-10-02T07:00:00Z', now)).toBe('5h old');
  });
  it('formats sizes, durations and digests', () => {
    expect(formatBytes(2048)).toBe('2.0 KB');
    expect(formatDuration(65_000)).toBe('1m 5s');
    expect(formatDuration(1500)).toBe('1.5s');
    expect(shortDigest('sha256:0123456789abcdef0123')).toBe('sha256:0123456789ab');
  });
});
