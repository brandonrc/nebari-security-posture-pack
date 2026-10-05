import type { Scan } from '@/api/types';

type Counts = Pick<
  Scan,
  'status' | 'imagesTotal' | 'imagesDone' | 'imagesInventoried' | 'imagesRescanned' | 'imagesSkippedFresh' | 'imagesTargeted'
>;

const n = (v: number | null | undefined): v is number => typeof v === 'number' && Number.isFinite(v);

/**
 * How many images a scan touched. `imagesTotal` is only what the scan attempted, so a
 * scheduled scan with everything still fresh reads 0/0; the accounting fields say why:
 * "68 rescanned · 12 fresh · 80 in inventory" (full scans) or
 * "3 targeted · 1 rescanned · 2 fresh" (event / targeted scans).
 * Scans from before the accounting columns fall back to "done/total".
 */
export function scanImageParts(s: Counts): string[] {
  if (!n(s.imagesInventoried)) return [`${s.imagesDone}/${s.imagesTotal}`];
  const running = s.status === 'running' || s.status === 'queued';
  const rescanned = running && s.imagesTotal ? `${s.imagesDone}/${s.imagesTotal}` : String(s.imagesRescanned ?? s.imagesDone);
  const parts: string[] = [];
  if (n(s.imagesTargeted)) parts.push(`${s.imagesTargeted} targeted`);
  parts.push(`${rescanned} rescanned`);
  if (n(s.imagesSkippedFresh)) parts.push(`${s.imagesSkippedFresh} fresh`);
  if (!n(s.imagesTargeted)) parts.push(`${s.imagesInventoried} in inventory`);
  return parts;
}

export function scanImageSummary(s: Counts): string {
  return scanImageParts(s).join(' · ');
}
