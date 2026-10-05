import { describe, expect, it } from 'vitest';
import { scanImageSummary, scapInProgress, scapLine } from './scan-counts';

const base = { status: 'done' as const, imagesTotal: 0, imagesDone: 0 };

describe('scanImageSummary', () => {
  it('explains a scheduled scan that rescanned only stale images', () => {
    expect(
      scanImageSummary({ ...base, imagesTotal: 68, imagesDone: 68, imagesInventoried: 80, imagesRescanned: 68, imagesSkippedFresh: 12, imagesTargeted: null }),
    ).toBe('68 rescanned · 12 fresh · 80 in inventory');
  });

  it('does not read 0/0 when everything was fresh', () => {
    expect(scanImageSummary({ ...base, imagesInventoried: 80, imagesRescanned: 0, imagesSkippedFresh: 80 })).toBe(
      '0 rescanned · 80 fresh · 80 in inventory',
    );
  });

  it('shows the target count of event scans', () => {
    expect(
      scanImageSummary({ ...base, imagesTotal: 1, imagesDone: 1, imagesInventoried: 80, imagesRescanned: 1, imagesSkippedFresh: 2, imagesTargeted: 3 }),
    ).toBe('3 targeted · 1 rescanned · 2 fresh');
  });

  it('shows progress while running and falls back for old scans', () => {
    expect(
      scanImageSummary({ status: 'running', imagesTotal: 10, imagesDone: 4, imagesInventoried: 80, imagesRescanned: 4, imagesSkippedFresh: 70 }),
    ).toBe('4/10 rescanned · 70 fresh · 80 in inventory');
    expect(scanImageSummary({ ...base, imagesTotal: 40, imagesDone: 39 })).toBe('39/40');
  });
});

describe('scapLine (§14)', () => {
  it('shows the STIG evaluation progress, also after the scan finished (scapPending)', () => {
    expect(scapLine({ scapStatus: 'running', scapImages: 83, scapProgress: { done: 12, total: 83 }, scapPending: true })).toBe('STIG evaluation in progress (12/83)');
    expect(scapLine({ scapStatus: 'queued', scapImages: 5, scapProgress: null })).toBe('STIG evaluation in progress (0/5)');
    expect(scapInProgress({ scapStatus: 'running' })).toBe(true);
  });

  it('is quiet when the stage is done, off or nothing was due', () => {
    expect(scapLine({ scapStatus: 'done', scapImages: 3, scapProgress: { done: 3, total: 3 }, scapPending: false })).toBeNull();
    expect(scapLine({ scapStatus: null })).toBeNull();
    expect(scapLine({})).toBeNull();
    expect(scapInProgress({ scapStatus: 'done', scapPending: false })).toBe(false);
  });

  it('names the gap between the stage finishing and the re-aggregation, and failures', () => {
    expect(scapLine({ scapStatus: 'done', scapPending: true })).toBe('STIG results being applied');
    expect(scapInProgress({ scapStatus: 'done', scapPending: true })).toBe(true);
    expect(scapLine({ scapStatus: 'failed', scapPending: false })).toBe('STIG evaluation failed');
  });
});
