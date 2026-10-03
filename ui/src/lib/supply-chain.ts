import type { Grade, HelmRelease, ImageProvenance, ImageSummary, SupplyChainDeduction, SupplyChainSummary, UpdateInfo, UpdateLevel } from '@/api/types';
import { gradeForScore } from './scoring';

/**
 * DESIGN §12 / SCORING.md supply-chain score per image: start 100;
 * −40 unsigned (−20 signed but unverified), −20 no SBOM, −15 no provenance,
 * −15 update available (−25 if a major version behind), −10 mutable tag
 * without digest pin; floor 0.
 *
 * A check the API didn't report (`undefined`/`null` member) is not penalised:
 * the UI must not invent deductions for checks that are disabled in settings.
 */
export const SUPPLY_CHAIN_PENALTY = {
  unsigned: 40,
  unverified: 20,
  noSbom: 20,
  noProvenance: 15,
  update: 15,
  majorUpdate: 25,
  mutableTag: 10,
} as const;

export interface SupplyChainScore {
  score: number;
  grade: Grade;
  deductions: SupplyChainDeduction[];
}

export function supplyChainDeductions(p: ImageProvenance | null | undefined, opts: { tag?: string | null } = {}): SupplyChainDeduction[] {
  const out: SupplyChainDeduction[] = [];
  if (!p) return out;
  const sig = p.signature;
  if (sig) {
    if (!sig.signed) out.push({ reason: 'Image is not signed', points: SUPPLY_CHAIN_PENALTY.unsigned });
    else if (!sig.verified) out.push({ reason: 'Signature present but not verified', points: SUPPLY_CHAIN_PENALTY.unverified });
  }
  if (p.sbom && !p.sbom.hasSBOM) out.push({ reason: 'No SBOM attestation', points: SUPPLY_CHAIN_PENALTY.noSbom });
  if (p.provenance && !p.provenance.hasProvenance) out.push({ reason: 'No SLSA provenance attestation', points: SUPPLY_CHAIN_PENALTY.noProvenance });
  if (p.update?.updateAvailable) {
    const level = updateLevel(p.update);
    out.push(
      level === 'major'
        ? { reason: `Major version behind (${p.update.newestAvailable ?? 'newer major'} available)`, points: SUPPLY_CHAIN_PENALTY.majorUpdate }
        : { reason: `Update available (${latestTag(p.update) ?? 'newer tag'})`, points: SUPPLY_CHAIN_PENALTY.update },
    );
  }
  const mutable = p.mutableTag ?? (opts.tag !== undefined ? isMutableTag(opts.tag) : false);
  if (mutable) out.push({ reason: 'Mutable tag without digest pin', points: SUPPLY_CHAIN_PENALTY.mutableTag });
  return out;
}

/** Client-side score; prefers the API's own score/deductions when present. */
export function supplyChainScore(p: ImageProvenance | null | undefined, opts: { tag?: string | null } = {}): SupplyChainScore | null {
  if (!p) return null;
  const deductions = p.deductions?.length ? p.deductions : supplyChainDeductions(p, opts);
  const computed = Math.max(0, 100 - deductions.reduce((a, d) => a + (Number.isFinite(d.points) ? Math.abs(d.points) : 0), 0));
  const score = typeof p.score === 'number' ? p.score : computed;
  return { score, grade: p.grade ?? gradeForScore(score), deductions };
}

export function isMutableTag(tag: string | null | undefined): boolean {
  return !tag || tag === 'latest';
}

interface SemVer {
  major: number;
  minor: number;
  patch: number;
}

/** Lenient semver parse: `v1.2.3`, `1.2`, `16.4.0-debian-12-r2` (suffix ignored). */
export function parseSemver(tag: string | null | undefined): SemVer | null {
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec((tag ?? '').trim());
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2] ?? 0), patch: Number(m[3] ?? 0) };
}

/** How far `current` is behind `latest`; null when equal, unparseable or ahead. */
export function semverDiff(current: string | null | undefined, latest: string | null | undefined): UpdateLevel | null {
  const a = parseSemver(current);
  const b = parseSemver(latest);
  if (!a || !b) return null;
  if (b.major !== a.major) return b.major > a.major ? 'major' : null;
  if (b.minor !== a.minor) return b.minor > a.minor ? 'minor' : null;
  return b.patch > a.patch ? 'patch' : null;
}

/** The tag to suggest: newest overall, else newest in the current major. */
export function latestTag(u: UpdateInfo | null | undefined): string | null {
  if (!u) return null;
  return u.newestAvailable || u.latestInMajor || null;
}

/** Update level: the API's `level` when given, else derived from the tags (unparseable → patch). */
export function updateLevel(u: UpdateInfo | null | undefined): UpdateLevel | null {
  if (!u?.updateAvailable) return null;
  if (u.level === 'major' || u.level === 'minor' || u.level === 'patch') return u.level;
  return semverDiff(u.currentTag, u.newestAvailable) ?? semverDiff(u.currentTag, u.latestInMajor) ?? 'patch';
}

/** SCORING.md cluster weights: 0.6/0.25/0.15 with supply chain, 0.7/0.3 before §12. */
export function clusterWeights(hasSupplyChain: boolean) {
  return hasSupplyChain ? { vuln: 0.6, posture: 0.25, supplyChain: 0.15 } : { vuln: 0.7, posture: 0.3, supplyChain: 0 };
}

export function clusterScore(vuln: number | null | undefined, posture: number | null | undefined, supplyChain?: number | null): number | null {
  if (vuln === null || vuln === undefined || posture === null || posture === undefined) return null;
  const w = clusterWeights(supplyChain !== null && supplyChain !== undefined);
  const total = w.vuln * vuln + w.posture * posture + w.supplyChain * (supplyChain ?? 0);
  return Math.round(total * 10) / 10;
}

export function percent(n: number | null | undefined, of: number | null | undefined): number | null {
  if (n === null || n === undefined || !of) return null;
  return Math.round((n / of) * 1000) / 10;
}

/**
 * Image is deployed as of the latest done scan. Stale images (`current: false`, e.g. old
 * tags no longer running) are left out of supply-chain counts and lists, like the API's
 * `GET /supply-chain` default; unknown (`null`/absent, before any scan) counts as current.
 */
export function isCurrentImage(i: Pick<ImageSummary, 'current'>): boolean {
  return i.current !== false;
}

/** Fallback when `GET /supply-chain` isn't available: derive the summary from current images + releases. */
export function deriveSupplyChainSummary(all: ImageSummary[], releases: HelmRelease[], score: number | null | undefined): SupplyChainSummary {
  const images = all.filter(isCurrentImage);
  const p = images.map((i) => i.provenance);
  const s = score ?? null;
  return {
    signed: p.filter((x) => x?.signature?.signed).length,
    verified: p.filter((x) => x?.signature?.verified).length,
    withSbom: p.filter((x) => x?.sbom?.hasSBOM).length,
    withProvenance: p.filter((x) => x?.provenance?.hasProvenance).length,
    withUpdates: p.filter((x) => x?.update?.updateAvailable).length,
    unique: images.length,
    helmReleases: releases.length,
    helmWithUpdates: releases.filter((r) => r.update?.updateAvailable).length,
    score: s,
    grade: gradeForScore(s),
    stale: all.length - images.length,
    includeStale: false,
  };
}
