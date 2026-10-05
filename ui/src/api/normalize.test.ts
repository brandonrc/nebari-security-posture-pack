import { describe, expect, it } from 'vitest';
import * as n from './normalize';
import type { ScapContentVersion } from './types';

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

describe('normalize: §14 SCAP shapes', () => {
  it.each(MALFORMED)('SCAP bodies (%j) become empty shapes', (raw) => {
    expect(n.imageStig(raw).benchmarks).toEqual([]);
    expect(n.complianceStig(raw).kubernetes).toEqual([]);
    const b = n.stigBenchmark(raw);
    expect([b.imagesEvaluated, b.pass, b.fail]).toEqual([0, 0, 0]);
    const r = n.stigBenchmarkRule(raw);
    expect([r.failingImages, r.passingImages, r.images, r.cat]).toEqual([0, 0, [], 'cat2']);
    expect(n.summary(raw).stig).toBe(typeof raw === 'object' && raw !== null && 'stig' in raw ? null : undefined);
  });

  it('complianceStig accepts the bare pre-§14 list, {items, product} and {kubernetes, product:{items}}', () => {
    expect(n.complianceStig([{ vulnId: 'V-1' }])).toEqual({ kubernetes: [{ vulnId: 'V-1' }], product: null });
    expect(n.complianceStig({ items: [{ vulnId: 'V-1' }], product: [{ benchmarkId: 'b1' }] }).product?.[0].id).toBe('b1');
    const c = n.complianceStig({ kubernetes: { items: [{ vulnId: 'V-2' }] }, product: { items: [{ id: 'b2', title: 'T' }] } });
    expect(c.kubernetes).toHaveLength(1);
    expect(c.product?.[0]).toMatchObject({ id: 'b2', title: 'T', imagesEvaluated: 0 });
    expect(n.complianceStig({ items: [] }).product).toBeNull();
  });

  it('imageStig reads paged rules from an array or a page envelope and tolerates spellings', () => {
    const s = n.imageStig({
      benchmarks: [
        { id: 'b', summary: { pass: 3, fail: 1, score: 88.2, profile: 'p1' }, rules: { items: [{ ruleId: 'r', cat: 'CAT I', cci: 'CCI-1 CCI-2' }], total: 40, page: 2, pageSize: 1 } },
      ],
      rootfsFidelity: 'degraded',
    });
    const b = s.benchmarks[0];
    expect(b).toMatchObject({ benchmarkId: 'b', title: 'b', profileId: 'p1', rulesTotal: 40, page: 2, pageSize: 1 });
    expect(b.summary).toMatchObject({ pass: 3, fail: 1, notchecked: 0, score: 88.2 });
    expect(b.rules[0]).toMatchObject({ severity: 'cat1', cci: ['CCI-1', 'CCI-2'], result: 'unknown', title: 'r', stigId: null });
    expect(s.rootfsFidelity).toBe('degraded');
  });

  it('imageSummary keeps stig null vs absent apart', () => {
    expect('stig' in n.imageSummary({ id: 'a' })).toBe(false);
    expect(n.imageSummary({ id: 'a', stig: null }).stig).toBeNull();
    expect(n.imageSummary({ id: 'a', stig: 'bad' }).stig).toBeNull();
    expect(n.imageSummary({ id: 'a', stig: { score: 70 } }).stig).toEqual({ score: 70 });
    expect(n.summary({ stig: { evaluated: 2, coverage: 0.5 } }).stig).toMatchObject({ evaluated: 2, pass: 0, fail: 0, cat1Open: 0, cat2Open: 0, cat3Open: 0, coverage: 0.5, score: null });
  });
});

describe('normalize: §14 API shapes (api/src/posture/routers/stig.py)', () => {
  it('numeric image ids become strings', () => {
    expect(n.imageSummary({ id: 42 }).id).toBe('42');
    expect(n.idStr(NaN)).toBe('');
  });

  it('image stig: summary fidelity/evaluatedAt, rootfs notes and status', () => {
    const s = n.imageStig({
      status: 'evaluated',
      rootfs: { fidelity: 'degraded', notes: ['ran as non-root'], droppedXattrs: 3, skippedDevices: 1, unsafeEntries: 2 },
      benchmarks: [{ benchmarkId: 'ssg-rhel9', summary: { pass: 1, rootfsFidelity: 'degraded', evaluatedAt: '2026-10-05T00:00:00Z' }, rules: [] }],
    });
    expect(s.status).toBe('evaluated');
    expect(s.rootfsFidelity).toBe('degraded');
    expect(s.rootfsWarnings).toEqual(['ran as non-root', '3 extended attributes could not be restored', '1 device files skipped', '2 unsafe layer entries refused']);
    expect(s.benchmarks[0]).toMatchObject({ rootfsFidelity: 'degraded', checkedAt: '2026-10-05T00:00:00Z' });
  });

  it('benchmark rules envelope with failing[] and the benchmark row', () => {
    const r = n.stigBenchmarkRules({
      benchmark: { id: 'b', title: 'B', imagesEvaluated: 2 },
      items: [{ ruleId: 'r', cat: 'cat1', failingImages: 1, passingImages: 1, otherImages: 0, failing: [{ imageId: 3, ref: 'a:1' }] }],
      total: 1,
    });
    expect(r.benchmark?.id).toBe('b');
    expect(r.total).toBe(1);
    expect(r.rules[0]).toMatchObject({ failingImages: 1, passingImages: 1, otherImages: 0, images: [{ imageId: '3', ref: 'a:1', result: 'fail' }] });
    expect(n.stigBenchmarkRules({ benchmark: { id: null }, items: [] }).benchmark).toBeNull();
  });

  it('scanner content[] becomes contentVersions', () => {
    const s = n.scanner<{ contentVersions?: ScapContentVersion[] }>({ name: 'scap', content: [{ file: 'ssg-rhel9-ds.xml', title: 'RHEL 9', version: '0.1.76' }, { file: 'x.xml' }] });
    expect(s.contentVersions).toEqual([
      expect.objectContaining({ name: 'RHEL 9', version: '0.1.76', file: 'ssg-rhel9-ds.xml' }),
      expect.objectContaining({ name: 'x.xml', version: null }),
    ]);
    expect(n.complianceStig({ items: [], product: { benchmarks: [{ id: 'b' }], evaluated: 1 } }).product?.[0].id).toBe('b');
  });
});
