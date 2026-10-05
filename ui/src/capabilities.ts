import { useSyncExternalStore } from 'react';
import { getConfig } from '@/config';

/**
 * Which backend the SPA is talking to.
 * - `posture`: the Security Posture API (`/api/v1`, gateway cookie auth) — every section.
 * - `provenance`: only provenance-collector-pack's Go dashboard (`/api/reports`, `/api/me`,
 *   `/api/scan`, `/api/export`; keycloak-js bearer auth) — the supply-chain subset.
 */
export type Mode = 'posture' | 'provenance';

/** UI sections; each sidebar entry and route is gated on one. */
export type Feature =
  | 'overview'
  | 'images'
  | 'imageFindings'
  | 'vulnerabilities'
  | 'workloads'
  | 'namespaces'
  | 'checks'
  | 'supplyChain'
  | 'helmReleases'
  | 'scans'
  | 'scanDetail'
  | 'reports'
  | 'compliance'
  | 'settings';

export type Features = Record<Feature, boolean>;

export interface Capabilities {
  mode: Mode;
  features: Features;
}

const ALL: Feature[] = [
  'overview',
  'images',
  'imageFindings',
  'vulnerabilities',
  'workloads',
  'namespaces',
  'checks',
  'supplyChain',
  'helmReleases',
  'scans',
  'scanDetail',
  'reports',
  'compliance',
  'settings',
];
const PROVENANCE_FEATURES: Feature[] = ['overview', 'images', 'supplyChain', 'helmReleases', 'scans', 'reports'];

export function capabilitiesFor(mode: Mode): Capabilities {
  const on = new Set<Feature>(mode === 'posture' ? ALL : PROVENANCE_FEATURES);
  return { mode, features: Object.fromEntries(ALL.map((f) => [f, on.has(f)])) as Features };
}

/**
 * Probe `GET {apiBase}/summary` once at startup. Any 2xx, 401 or 403 (and 5xx: the posture API
 * exists but is unhealthy — keep its error states) → `posture`. 404 or a network error →
 * `provenance` (the Go dashboard answers unknown `/api/v1/*` paths with 404).
 * `mode` in `/config.json` short-circuits the probe.
 */
export async function detectCapabilities(fetchImpl: typeof fetch = fetch): Promise<Capabilities> {
  const { apiBase, mode } = getConfig();
  if (mode === 'posture' || mode === 'provenance') return capabilitiesFor(mode);
  try {
    const res = await fetchImpl(`${apiBase}/summary`, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
    if (res.status === 404) return capabilitiesFor('provenance');
    // an HTML 200 is a static host's SPA fallback, not the posture API
    const type = res.headers.get('content-type') ?? '';
    if (res.ok && type.includes('text/html')) return capabilitiesFor('provenance');
    return capabilitiesFor('posture');
  } catch {
    return capabilitiesFor('provenance');
  }
}

let current: Capabilities = capabilitiesFor('posture');
const listeners = new Set<() => void>();

export function getCapabilities(): Capabilities {
  return current;
}

export function isProvenanceMode(): boolean {
  return current.mode === 'provenance';
}

export function setCapabilities(next: Capabilities | Mode): void {
  current = typeof next === 'string' ? capabilitiesFor(next) : next;
  for (const l of listeners) l();
}

export function resetCapabilities(): void {
  setCapabilities('posture');
}

export function useCapabilities(): Capabilities {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => current,
    () => current,
  );
}

/** Product name for the header / document title. */
export function productTitle(caps: Capabilities = current): string {
  return getConfig().title || (caps.mode === 'provenance' ? 'Supply-chain provenance' : 'Security Posture');
}
