import { describe, expect, it } from 'vitest';
import * as n from './normalize';

const MALFORMED = [undefined, null, [], {}, 'text', 42, { items: null }];

describe('normalize: malformed bodies become empty, iterable shapes', () => {
  it.each(MALFORMED)('summary(%j)', (raw) => {
    const s = n.summary(raw);
    expect(s.grade).toBe('?');
    expect(s.score).toBeNull();
    expect(s.counts).toEqual({ critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0 });
    expect(s.scanners).toEqual([]);
    expect(s.topRisks).toEqual([]);
    expect(s.trend).toEqual([]);
    expect(s.checks).toEqual({ passed: 0, failed: 0, total: 0 });
    expect(s.images).toEqual({ total: 0, scanned: 0, failed: 0 });
    expect(s.lastScan).toBeNull();
  });

  it.each(MALFORMED)('image detail / vuln detail / check / supply chain / settings (%j)', (raw) => {
    const img = n.imageDetail(raw);
    expect([img.findings, img.usedBy, img.scans, img.postureFindings, img.namespaces, img.warnings]).toEqual([[], [], [], [], [], []]);
    expect(img.repository).toBe('');
    expect(n.vulnDetail(raw).images).toEqual([]);
    expect(n.checkDetail(raw)).toMatchObject({ results: [], controls: [], passed: 0, failed: 0 });
    expect(n.supplyChain(raw)).toMatchObject({ signed: 0, grade: '?', score: null });
    expect(n.settings(raw)).toMatchObject({ excludedNamespaces: [], adminGroups: [], scanners: { trivy: false, grype: false, clair: false } });
    expect(n.vulnList(raw)).toMatchObject({ items: [], total: 0 });
  });
});

describe('normalize: well-formed bodies pass through', () => {
  it('keeps served values and fills only missing containers', () => {
    const s = n.summary({ score: 87.5, grade: 'B', counts: { critical: 2 }, scanners: [{ name: 'trivy' }], images: { total: 3, scanned: 2, failed: 1 } });
    expect(s).toMatchObject({ score: 87.5, grade: 'B', images: { total: 3, scanned: 2, failed: 1 } });
    expect(s.counts.critical).toBe(2);
    expect(s.counts.high).toBe(0);
    expect(s.scanners).toHaveLength(1);
  });

  it('pages accept a bare array or an envelope', () => {
    expect(n.page([{ id: 'a' }], n.imageSummary)).toMatchObject({ items: [{ id: 'a' }], total: 1, page: 1, pageSize: 1 });
    const p = n.page({ items: [{ id: 'a', grade: 'C', counts: { high: 1 } }], total: 40, page: 2, pageSize: 25 }, n.imageSummary);
    expect(p).toMatchObject({ total: 40, page: 2, pageSize: 25 });
    expect(p.items[0]).toMatchObject({ id: 'a', grade: 'C', scanners: {}, namespaces: [] });
    expect(p.items[0].counts.high).toBe(1);
  });

  it('settings keep served toggles and only default reports when present', () => {
    expect(n.settings({ scanners: { trivy: true }, scanIntervalHours: 24 })).toMatchObject({
      scanIntervalHours: 24,
      scanners: { trivy: true, grype: false, clair: false },
    });
    expect(n.settings({}).reports).toBeUndefined();
    expect(n.settings({ reports: {} }).reports).toEqual({ autoGenerate: [] });
  });

  it('helpers', () => {
    expect(n.obj([1])).toEqual({});
    expect(n.arr({ length: 1 })).toEqual([]);
    expect(n.counts({ high: 'x', low: Number.NaN, medium: 4 })).toMatchObject({ high: 0, low: 0, medium: 4 });
  });
});
