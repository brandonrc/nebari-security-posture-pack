import { describe, expect, it } from 'vitest';
import { coveragePct, fidelityDegraded, imageStigScore, normCat, normResult, passRate, SOURCE_LABEL, stigGrade } from './stig';

describe('lib/stig', () => {
  it.each([
    ['cat1', 'cat1'],
    ['CAT I', 'cat1'],
    ['high', 'cat1'],
    ['I', 'cat1'],
    ['CAT_II', 'cat2'],
    ['medium', 'cat2'],
    ['', 'cat2'],
    ['cat3', 'cat3'],
    ['III', 'cat3'],
    ['low', 'cat3'],
  ])('normCat(%j) = %s', (input, out) => expect(normCat(input)).toBe(out));

  it.each([
    ['pass', 'pass'],
    ['FAIL', 'fail'],
    ['not_applicable', 'notapplicable'],
    ['notapplicable', 'notapplicable'],
    ['not-checked', 'notchecked'],
    ['notselected', 'notchecked'],
    ['error', 'error'],
    ['informational', 'informational'],
    ['fixed', 'pass'],
    ['weird', 'unknown'],
    [null, 'unknown'],
  ])('normResult(%j) = %s', (input, out) => expect(normResult(input)).toBe(out));

  it('coverage, pass rate, source labels, grade and fidelity', () => {
    expect(coveragePct(0.25)).toBe(25);
    expect(coveragePct(40)).toBe(40);
    expect(coveragePct(140)).toBe(100);
    expect(coveragePct(null)).toBeNull();
    expect(passRate(3, 1)).toBe(75);
    expect(passRate(0, 0)).toBeNull();
    expect([SOURCE_LABEL('disa'), SOURCE_LABEL('SSG'), SOURCE_LABEL('custom'), SOURCE_LABEL(null)]).toEqual(['DISA', 'SSG', 'CUSTOM', '—']);
    expect(stigGrade(92)).toBe('A');
    expect(stigGrade(null)).toBe('?');
    expect(fidelityDegraded('degraded')).toBe(true);
    expect(fidelityDegraded('full')).toBe(false);
    expect(fidelityDegraded(null)).toBe(false);
    expect(imageStigScore({})).toBeUndefined();
    expect(imageStigScore({ stig: null })).toBeNull();
    expect(imageStigScore({ stig: { score: 81 } })).toBe(81);
  });
});
