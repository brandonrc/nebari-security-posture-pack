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

type ScapFields = Pick<Scan, 'scapStatus' | 'scapImages' | 'scapProgress' | 'scapPending'>;

/** The scan's SCAP stage is still evaluating (queued / running) or its results are not folded in yet. */
export function scapInProgress(s: ScapFields): boolean {
  return s.scapStatus === 'queued' || s.scapStatus === 'running' || Boolean(s.scapPending);
}

/**
 * §14 SCAP stage of a scan: "STIG evaluation in progress (12/83)" while queued / running (the
 * scan itself may already be done: `scapPending`), "STIG results being applied" between the stage
 * finishing and the re-aggregation, "STIG evaluation failed", or null (off / nothing to show).
 */
export function scapLine(s: ScapFields): string | null {
  if (!s.scapStatus) return null;
  const total = s.scapProgress?.total ?? s.scapImages ?? 0;
  const done = Math.min(s.scapProgress?.done ?? 0, total);
  if (s.scapStatus === 'queued' || s.scapStatus === 'running') return `STIG evaluation in progress (${done}/${total})`;
  if (s.scapStatus === 'failed') return 'STIG evaluation failed';
  if (s.scapPending) return 'STIG results being applied';
  return null;
}
