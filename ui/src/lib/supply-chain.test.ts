import { describe, expect, it } from 'vitest';
import { normalizeControlStatus, baselineCoverage, inBaseline, lowestBaseline, rollupFamilies, compareControlId } from './controls';
import { clusterScore, clusterWeights, deriveSupplyChainSummary, isCurrentImage, latestTag, parseSemver, semverDiff, supplyChainDeductions, supplyChainScore, updateLevel } from './supply-chain';

const signedVerified = { signed: true, verified: true };

describe('supplyChainScore (DESIGN §12)', () => {
  it('is 100 for a signed, verified, attested, current, pinned image', () => {
    const s = supplyChainScore({ signature: signedVerified, sbom: { hasSBOM: true }, provenance: { hasProvenance: true }, update: { currentTag: '1.0.0', updateAvailable: false } }, { tag: '1.0.0' });
    expect(s).toMatchObject({ score: 100, grade: 'A', deductions: [] });
  });

  it('applies every deduction and floors at 0', () => {
    const s = supplyChainScore(
      { signature: { signed: false, verified: false }, sbom: { hasSBOM: false }, provenance: { hasProvenance: false }, update: { currentTag: '1.0.0', newestAvailable: '2.1.0', updateAvailable: true } },
      { tag: 'latest' },
    );
    // 40 + 20 + 15 + 25 + 10 = 110 → floor 0
    expect(s?.deductions.map((d) => d.points)).toEqual([40, 20, 15, 25, 10]);
    expect(s?.score).toBe(0);
    expect(s?.grade).toBe('F');
  });

  it('charges 20 for signed-but-unverified and 15 for a non-major update', () => {
    const d = supplyChainDeductions({ signature: { signed: true, verified: false }, update: { currentTag: 'v1.2.0', newestAvailable: 'v1.4.1', updateAvailable: true } }, { tag: 'v1.2.0' });
    expect(d.map((x) => x.points)).toEqual([20, 15]);
  });

  it('does not penalise checks that did not run', () => {
    expect(supplyChainScore({ signature: signedVerified }, { tag: '1.0' })?.score).toBe(100);
    expect(supplyChainScore(null)).toBeNull();
  });

  it('prefers the API score and deductions when present', () => {
    const s = supplyChainScore({ score: 42, deductions: [{ reason: 'x', points: 58 }], signature: signedVerified });
    expect(s).toMatchObject({ score: 42, grade: 'F', deductions: [{ reason: 'x', points: 58 }] });
  });

  it('honours an explicit mutableTag flag over the tag heuristic', () => {
    expect(supplyChainDeductions({ mutableTag: false }, { tag: 'latest' })).toEqual([]);
    expect(supplyChainDeductions({ mutableTag: true }, { tag: '1.0' }).map((d) => d.points)).toEqual([10]);
  });
});

describe('semver helpers', () => {
  it('parses lenient tags', () => {
    expect(parseSemver('v1.2.3')).toEqual({ major: 1, minor: 2, patch: 3 });
    expect(parseSemver('16.4.0-debian-12-r2')).toEqual({ major: 16, minor: 4, patch: 0 });
    expect(parseSemver('3.9-slim')).toEqual({ major: 3, minor: 9, patch: 0 });
    expect(parseSemver('latest')).toBeNull();
  });
  it('classifies how far behind', () => {
    expect(semverDiff('1.2.3', '2.0.0')).toBe('major');
    expect(semverDiff('1.2.3', '1.3.0')).toBe('minor');
    expect(semverDiff('1.2.3', '1.2.9')).toBe('patch');
    expect(semverDiff('1.2.3', '1.2.3')).toBeNull();
    expect(semverDiff('2.0.0', '1.9.9')).toBeNull();
  });
  it('derives the update level, preferring the API value', () => {
    expect(updateLevel({ currentTag: 'v2.55.0', newestAvailable: 'v3.5.0', latestInMajor: 'v2.55.1', updateAvailable: true })).toBe('major');
    expect(updateLevel({ currentTag: 'distroless-v1', newestAvailable: 'distroless-v2', updateAvailable: true, level: 'minor' })).toBe('minor');
    expect(updateLevel({ currentTag: 'a', newestAvailable: 'b', updateAvailable: true })).toBe('patch');
    expect(updateLevel({ currentTag: '1.0', updateAvailable: false })).toBeNull();
    expect(latestTag({ currentTag: '1', latestInMajor: '1.5', updateAvailable: true })).toBe('1.5');
  });
});

describe('cluster weights (SCORING.md)', () => {
  it('uses 0.6/0.25/0.15 with supply chain and 0.7/0.3 without', () => {
    expect(clusterWeights(true)).toEqual({ vuln: 0.6, posture: 0.25, supplyChain: 0.15 });
    expect(clusterScore(80, 60, 40)).toBe(69);
    expect(clusterScore(80, 60)).toBe(74);
    expect(clusterScore(null, 60, 40)).toBeNull();
  });
});

describe('control helpers (DESIGN §13)', () => {
  it('normalises status spellings', () => {
    expect(normalizeControlStatus('satisfied')).toBe('implemented');
    expect(normalizeControlStatus('not-satisfied')).toBe('not-implemented');
    expect(normalizeControlStatus('planned')).toBe('not-implemented');
    expect(normalizeControlStatus('Not Applicable')).toBe('not-applicable');
    expect(normalizeControlStatus(undefined)).toBe('unknown');
  });
  it('treats baselines as nested', () => {
    expect(inBaseline('low', 'moderate')).toBe(true);
    expect(inBaseline('high', 'moderate')).toBe(false);
    expect(inBaseline(['moderate', 'high'], 'low')).toBe(false);
    expect(inBaseline(null, 'high')).toBe(false);
    expect(lowestBaseline(['high', 'moderate'])).toBe('moderate');
  });
  it('rolls up families and baseline coverage from a bare §11 list', () => {
    const list = [
      { control: 'AC-6', title: '', findingsOpen: 0, checksFailed: 2, status: 'not-satisfied', baseline: 'moderate' },
      { control: 'AC-7', title: '', findingsOpen: 0, checksFailed: 0, status: 'implemented', baseline: 'low' },
      { control: 'SC-12(1)', title: '', findingsOpen: 0, checksFailed: 0, status: 'implemented', baseline: 'high' },
      { control: 'AC-1', title: '', findingsOpen: 0, checksFailed: 0, status: 'inherited', baseline: 'low' },
    ];
    expect(rollupFamilies(list)).toEqual([
      { family: 'AC', title: 'Access Control', implemented: 1, partial: 0, notImplemented: 1, inherited: 1, notApplicable: 0, unknown: 0 },
      { family: 'SC', title: 'System and Communications Protection', implemented: 1, partial: 0, notImplemented: 0, inherited: 0, notApplicable: 0, unknown: 0 },
    ]);
    expect(baselineCoverage(list, 'moderate')).toEqual({ implemented: 1, inherited: 1, total: 3 });
  });
  it('orders control ids naturally', () => {
    expect(['AC-10', 'AC-2(1)', 'AC-2', 'AU-2'].sort(compareControlId)).toEqual(['AC-2', 'AC-2(1)', 'AC-10', 'AU-2']);
  });
});

describe('deriveSupplyChainSummary (fallback without GET /supply-chain)', () => {
  const img = (id: string, current: boolean | null | undefined, signed: boolean) =>
    ({ id, ref: id, current, provenance: { signature: { signed, verified: false }, update: { currentTag: '1', updateAvailable: !signed } } }) as unknown as import('@/api/types').ImageSummary;

  it('counts only images in the latest done scan (stale ones excluded)', () => {
    const s = deriveSupplyChainSummary([img('a', true, true), img('b', true, false), img('old', false, false), img('new', undefined, false)], [], 50);
    expect(s).toMatchObject({ unique: 3, signed: 1, withUpdates: 2, stale: 1, score: 50 });
  });

  it('treats unknown currency (before any scan) as current', () => {
    expect(isCurrentImage({ current: null })).toBe(true);
    expect(isCurrentImage({})).toBe(true);
    expect(isCurrentImage({ current: false })).toBe(false);
  });
});
