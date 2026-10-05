import { describe, expect, it, vi } from 'vitest';
import {
  adaptMe,
  adaptReport,
  clearReportCache,
  getDataset,
  loadDataset,
  parseImageRef,
  queryImages,
  reportDeltas,
  SCHEMA_FIELD_MAP,
  setDataset,
  weightedScore,
} from '@/api/provenance-adapter';
import type { PcProvenanceReport, PcReportEntry } from '@/api/provenance-report';
import { goldenReport } from '@/mocks/provenance-backend';
import schema from '@/mocks/fixtures/report.schema.json';

const golden = () => adaptReport(structuredClone(goldenReport));

describe('schema coverage', () => {
  it('maps every property of every report.schema.json definition', () => {
    const defs = (schema as { $defs: Record<string, { properties?: Record<string, unknown> }> }).$defs;
    for (const [name, def] of Object.entries(defs)) {
      expect(Object.keys(SCHEMA_FIELD_MAP[name] ?? {}).sort(), `$defs.${name}`).toEqual(Object.keys(def.properties ?? {}).sort());
    }
    expect(Object.keys(SCHEMA_FIELD_MAP).sort()).toEqual(Object.keys(defs).sort());
  });

  it('every field lands in the adapted shapes (fully populated report)', () => {
    const full: PcProvenanceReport = {
      metadata: { schemaVersion: '1.1.0', generatedAt: '2026-10-04T08:00:00Z', collectorVersion: 'v1.2.3', clusterName: 'prod', namespacesScanned: ['apps'] },
      images: [
        {
          image: 'ghcr.io/acme/api:2.3.4',
          digest: 'sha256:abc',
          namespace: 'apps',
          workload: { kind: 'StatefulSet', name: 'api' },
          signature: { signed: true, verified: false, error: 'no matching signatures' },
          sbom: { hasSBOM: true, format: 'cyclonedx' },
          provenance: { hasProvenance: true, predicateType: 'https://slsa.dev/provenance/v1' },
          update: { currentTag: '2.3.4', latestInMajor: '2.9.0', newestAvailable: '3.0.0', updateAvailable: true },
        },
      ],
      helmReleases: [
        {
          releaseName: 'api',
          namespace: 'apps',
          chart: 'api',
          version: '1.0.0',
          appVersion: '2.3.4',
          status: 'deployed',
          update: { currentTag: '1.0.0', latestInMajor: '1.2.0', newestAvailable: '1.2.0', updateAvailable: true },
        },
      ],
      summary: {
        totalImages: 1,
        uniqueImages: 1,
        signedImages: 1,
        verifiedImages: 0,
        imagesWithSBOM: 1,
        imagesWithProvenance: 1,
        imagesWithUpdates: 1,
        totalHelmReleases: 1,
        helmReleasesWithUpdates: 1,
      },
      warnings: ['image ghcr.io/acme/api:2.3.4: slow registry'],
    };
    const a = adaptReport(full, 'provenance-20261004-080000.json');
    expect(a.meta).toEqual({
      filename: 'provenance-20261004-080000.json',
      schemaVersion: '1.1.0',
      generatedAt: '2026-10-04T08:00:00Z',
      collectorVersion: 'v1.2.3',
      clusterName: 'prod',
      namespacesScanned: ['apps'],
      totalImages: 1,
      summary: full.summary,
      warnings: ['image ghcr.io/acme/api:2.3.4: slow registry'],
    });
    const [img] = a.images;
    expect(img).toMatchObject({
      id: 'ghcr.io/acme/api:2.3.4',
      ref: 'ghcr.io/acme/api:2.3.4',
      registry: 'ghcr.io',
      repository: 'acme/api',
      tag: '2.3.4',
      digest: 'sha256:abc',
      namespaces: ['apps'],
      workloads: 1,
      containers: 1,
      lastScannedAt: '2026-10-04T08:00:00Z',
      warnings: ['image ghcr.io/acme/api:2.3.4: slow registry'],
      grade: '?',
      score: null,
    });
    expect(img.provenance).toMatchObject({
      checkedAt: '2026-10-04T08:00:00Z',
      signature: { signed: true, verified: false, error: 'no matching signatures' },
      sbom: { hasSBOM: true, format: 'cyclonedx' },
      provenance: { hasProvenance: true, predicateType: 'https://slsa.dev/provenance/v1' },
      update: { currentTag: '2.3.4', latestInMajor: '2.9.0', newestAvailable: '3.0.0', updateAvailable: true },
      mutableTag: false,
      // −20 unverified, −25 major update
      score: 55,
      grade: 'D',
    });
    expect(a.details.get(img.id)?.usedBy).toEqual([{ namespace: 'apps', kind: 'StatefulSet', name: 'api', container: '', running: true }]);
    expect(a.helmReleases).toEqual([
      {
        releaseName: 'api',
        namespace: 'apps',
        chart: 'api',
        version: '1.0.0',
        appVersion: '2.3.4',
        status: 'deployed',
        update: { currentTag: '1.0.0', latestInMajor: '1.2.0', newestAvailable: '1.2.0', updateAvailable: true },
      },
    ]);
    expect(a.supplyChain).toMatchObject({ signed: 1, verified: 0, withSbom: 1, withProvenance: 1, withUpdates: 1, unique: 1, helmReleases: 1, helmWithUpdates: 1, score: 55, grade: 'D' });
  });
});

describe('adaptReport on the golden report', () => {
  it('groups records by image reference, matching the collector’s uniqueImages', () => {
    const a = golden();
    expect(a.images.map((i) => i.ref)).toEqual([
      'ghcr.io/example/unreachable:0.1.0',
      'ghcr.io/example/web:1.4.2',
      'busybox:1.36',
      'registry.k8s.io/coredns/coredns:v1.11.1',
      'quay.io/prometheus/prometheus:v2.53.0',
    ]);
    expect(a.images).toHaveLength(goldenReport.summary.uniqueImages);
    const busybox = a.images[2];
    expect(busybox).toMatchObject({ registry: 'docker.io', repository: 'library/busybox', tag: '1.36', namespaces: ['default', 'monitoring'], workloads: 2, containers: 2 });
    expect(a.details.get('busybox:1.36')?.usedBy.map((u) => `${u.namespace}/${u.kind}/${u.name}`)).toEqual([
      'default/ReplicaSet/web-7d9f',
      'monitoring/StatefulSet/prometheus',
    ]);
  });

  it('tells "not found" from "not checked" and scores each image', () => {
    const a = golden();
    expect(a.checks).toEqual({ signature: true, sbom: true, provenance: true, update: true });
    const by = Object.fromEntries(a.images.map((i) => [i.repository, i.provenance]));
    // digest unresolved → never reached the registry: only the signature error, no other deductions
    expect(by['example/unreachable']).toMatchObject({ signature: { signed: false, error: expect.stringContaining('401') }, score: 60, grade: 'D' });
    expect(by['example/unreachable']?.sbom).toBeUndefined();
    expect(by['example/unreachable']?.update).toBeUndefined();
    // resolved and absent → negative
    expect(by['library/busybox']).toMatchObject({ sbom: { hasSBOM: false }, provenance: { hasProvenance: false }, update: { currentTag: '1.36', updateAvailable: false }, score: 25, grade: 'F' });
    expect(by['example/web']).toMatchObject({ score: 75, grade: 'C' });
    expect(by['example/web']?.deductions).toEqual([{ reason: 'Major version behind (2.0.1 available)', points: 25 }]);
    expect(by['coredns/coredns']?.score).toBe(45);
    expect(by['prometheus/prometheus']).toMatchObject({ sbom: { hasSBOM: true, format: 'cyclonedx' }, score: 45 });
    expect(a.images[0].warnings).toEqual([goldenReport.warnings?.[1]]);
  });

  it('builds the supply-chain summary, Helm releases and namespaces', () => {
    const a = golden();
    expect(a.supplyChain).toEqual({
      signed: 2,
      verified: 1,
      withSbom: 2,
      withProvenance: 1,
      withUpdates: 1,
      unique: 5,
      helmReleases: 2,
      helmWithUpdates: 0,
      // (60 + 75 + 25·2 + 45 + 45) / 6 containers
      score: 45.8,
      grade: 'F',
      stale: 0,
      includeStale: false,
    });
    expect(a.helmReleases.map((h) => [h.releaseName, h.status, h.update])).toEqual([
      ['prometheus', 'deployed', { currentTag: '25.8.0', updateAvailable: false }],
      ['web', 'failed', { currentTag: '0.3.1', updateAvailable: false }],
    ]);
    expect(a.namespaces.map((n) => [n.name, n.images, n.workloads])).toEqual([
      ['default', 3, 2],
      ['kube-system', 1, 1],
      ['monitoring', 2, 1],
    ]);
    expect(a.meta).toMatchObject({ schemaVersion: '1.1.0', collectorVersion: 'v0.0.0-golden', clusterName: 'golden', totalImages: 6 });
    expect(a.meta.warnings).toHaveLength(2);
  });

  it('leaves checks a report never ran as "not checked"', () => {
    const r = structuredClone(goldenReport);
    r.images = r.images.map(({ image, digest, namespace, workload }) => ({ image, digest, namespace, workload }));
    r.helmReleases = [];
    const a = adaptReport(r);
    expect(a.checks).toEqual({ signature: false, sbom: false, provenance: false, update: false });
    expect(a.images.every((i) => i.provenance === null)).toBe(true);
    expect(a.supplyChain.score).toBeNull();
    expect(a.supplyChain.grade).toBe('?');
  });

  it('survives a malformed or pre-1.1 body', () => {
    const a = adaptReport({ metadata: { generatedAt: '2025-01-01T00:00:00Z' }, images: null, summary: null } as unknown as PcProvenanceReport);
    expect(a.images).toEqual([]);
    expect(a.meta).toMatchObject({ schemaVersion: '1.0.0', clusterName: null, warnings: [], totalImages: 0, summary: null });
    expect(adaptReport(null as unknown as PcProvenanceReport).images).toEqual([]);
  });
});

describe('helpers', () => {
  it.each([
    ['busybox', { registry: 'docker.io', repository: 'library/busybox', tag: null, pinned: null }],
    ['bitnami/redis:7.2', { registry: 'docker.io', repository: 'bitnami/redis', tag: '7.2', pinned: null }],
    ['localhost:5000/app:dev', { registry: 'localhost:5000', repository: 'app', tag: 'dev', pinned: null }],
    ['quay.io/org/img@sha256:feed', { registry: 'quay.io', repository: 'org/img', tag: null, pinned: 'sha256:feed' }],
    ['ghcr.io/o/i:1.0@sha256:beef', { registry: 'ghcr.io', repository: 'o/i', tag: '1.0', pinned: 'sha256:beef' }],
  ])('parseImageRef(%s)', (ref, expected) => {
    expect(parseImageRef(ref)).toEqual(expected);
  });

  it('flags mutable tags without a digest pin', () => {
    const r = structuredClone(goldenReport);
    r.images = [
      { ...r.images[1], image: 'ghcr.io/example/web:latest' },
      { ...r.images[1], image: 'ghcr.io/example/web@sha256:1111' },
    ];
    const [latest, pinned] = adaptReport(r).images;
    expect(latest.provenance?.mutableTag).toBe(true);
    expect(latest.provenance?.deductions?.map((d) => d.points)).toContain(10);
    expect(pinned.provenance?.mutableTag).toBe(false);
  });

  it('queryImages filters, sorts and pages client-side', () => {
    const a = golden();
    expect(queryImages(a, { namespace: 'monitoring' }).items.map((i) => i.repository)).toEqual(['library/busybox', 'prometheus/prometheus']);
    expect(queryImages(a, { q: 'WEB' }).total).toBe(1);
    expect(queryImages(a, { q: 'sha256:3333' }).items[0].repository).toBe('prometheus/prometheus');
    expect(queryImages(a, { grade: 'F' }).total).toBe(3);
    expect(queryImages(a, { sort: 'score', order: 'asc' }).items[0].repository).toBe('library/busybox');
    expect(queryImages(a, { sort: 'score', order: 'desc' }).items[0].repository).toBe('example/web');
    expect(queryImages(a, { sort: 'workloads', order: 'desc' }).items[0].repository).toBe('library/busybox');
    expect(queryImages(a, { sort: 'namespace' }).items.at(-1)?.repository).toBe('prometheus/prometheus');
    const page2 = queryImages(a, { sort: 'ref', page: 2, pageSize: 2 });
    expect(page2).toMatchObject({ total: 5, page: 2, pageSize: 2 });
    expect(page2.items.map((i) => i.ref)).toEqual(['ghcr.io/example/web:1.4.2', 'quay.io/prometheus/prometheus:v2.53.0']);
  });

  it('weightedScore weights by containers and skips unscored images', () => {
    expect(weightedScore([])).toBeNull();
    const a = golden();
    expect(weightedScore(a.images.slice(1, 3))).toBe(Math.round(((75 + 25 * 2) / 3) * 10) / 10);
  });

  it('adaptMe maps /api/me onto Me (+ canRunScan / features)', () => {
    expect(adaptMe({ authEnabled: true, email: 'a@x', groups: ['admin'], canRunScan: true, features: { timelineDeltas: true } }, { name: 'Ada', email: 'a@x' })).toEqual({
      username: 'Ada',
      email: 'a@x',
      groups: ['admin'],
      isAdmin: true,
      canRunScan: true,
      authEnabled: true,
      features: { timelineDeltas: true },
    });
    expect(adaptMe({ authEnabled: false, canRunScan: false }, null)).toMatchObject({ username: 'Anonymous', canRunScan: false, features: { timelineDeltas: false } });
    expect(adaptMe({ authEnabled: true, canRunScan: false }, null).username).toBe('Signed in');
    expect(adaptMe(null, { name: '', email: 'b@x' }).username).toBe('b@x');
  });

  it('reportDeltas compares each entry with the next-older one', () => {
    const e = (filename: string, uniqueImages: number) => ({ filename, generatedAt: '', summary: { uniqueImages } }) as PcReportEntry;
    expect([...reportDeltas([e('c', 5), e('b', 3), e('a', 4)])]).toEqual([
      ['c', 2],
      ['b', -1],
      ['a', null],
    ]);
  });
});

describe('dataset + cache', () => {
  it('caches timestamped reports, re-reads latest after the TTL, evicts failures', async () => {
    clearReportCache();
    const fetchReport = vi.fn(async (name: string) => {
      if (name === 'broken.json') throw new Error('boom');
      return structuredClone(goldenReport);
    });
    await loadDataset(fetchReport, 'a.json');
    await loadDataset(fetchReport, 'a.json');
    expect(fetchReport).toHaveBeenCalledTimes(1);
    const now = Date.now();
    const spy = vi.spyOn(Date, 'now').mockReturnValue(now);
    expect((await loadDataset(fetchReport, null)).meta.filename).toBeNull();
    await loadDataset(fetchReport, null);
    expect(fetchReport).toHaveBeenCalledTimes(2);
    spy.mockReturnValue(now + 16_000);
    await loadDataset(fetchReport, null);
    expect(fetchReport).toHaveBeenCalledTimes(3);
    spy.mockRestore();
    await expect(loadDataset(fetchReport, 'broken.json')).rejects.toThrow('boom');
    await expect(loadDataset(fetchReport, 'broken.json')).rejects.toThrow('boom');
    expect(fetchReport).toHaveBeenCalledTimes(5);
  });

  it('setDataset switches the active report', async () => {
    const fetchReport = vi.fn(async () => structuredClone(goldenReport));
    setDataset('provenance-20261002-120000.json');
    expect(getDataset()).toBe('provenance-20261002-120000.json');
    await loadDataset(fetchReport);
    expect(fetchReport).toHaveBeenCalledWith('provenance-20261002-120000.json');
    setDataset(null);
    expect(getDataset()).toBeNull();
  });
});
