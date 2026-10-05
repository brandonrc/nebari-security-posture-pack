/** Keycloak client settings, as rendered by provenance-collector-pack's `frontend-configmap.yaml`. */
export interface KeycloakConfig {
  url: string;
  realm: string;
  clientId: string;
}

export type ModeOverride = 'auto' | 'posture' | 'provenance';

export interface RuntimeConfig {
  /** Posture API base (`/api/v1`). Probed at startup to pick the mode. */
  apiBase: string;
  /** provenance-collector dashboard API base (`/api` → `/api/reports`, `/api/me`, …). */
  provenanceApiBase: string;
  /** Product title shown in the header and tab; empty → the mode's default. */
  title: string;
  /** Present (all three keys non-empty) → keycloak-js PKCE login in provenance mode. */
  keycloak: KeycloakConfig | null;
  /** `auto` (default) probes `${apiBase}/summary`; `posture`/`provenance` skip the probe. */
  mode: ModeOverride;
}

const DEFAULT_CONFIG: RuntimeConfig = {
  apiBase: '/api/v1',
  provenanceApiBase: '/api',
  title: '',
  keycloak: null,
  mode: 'auto',
};

let current: RuntimeConfig = { ...DEFAULT_CONFIG };

const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null);
const base = (v: unknown, fallback: string) => str(v)?.replace(/\/+$/, '') ?? fallback;

function parseKeycloak(v: unknown): KeycloakConfig | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as Record<string, unknown>;
  const url = str(o.url);
  const realm = str(o.realm);
  const clientId = str(o.clientId);
  return url && realm && clientId ? { url: url.replace(/\/+$/, ''), realm, clientId } : null;
}

/**
 * Normalises a `/config.json` body. Accepts both this pack's keys (`apiBase`, `title`, `mode`,
 * `provenanceApiBase`) and provenance-collector-pack's (`keycloak.{url,realm,clientId}`, `title`,
 * plus branding keys that are ignored). Unknown or malformed values fall back to the defaults.
 */
export function parseConfig(data: unknown): RuntimeConfig {
  const o = data && typeof data === 'object' ? (data as Record<string, unknown>) : {};
  const mode = o.mode === 'posture' || o.mode === 'provenance' ? o.mode : 'auto';
  return {
    apiBase: base(o.apiBase, DEFAULT_CONFIG.apiBase),
    provenanceApiBase: base(o.provenanceApiBase, DEFAULT_CONFIG.provenanceApiBase),
    title: str(o.title) ?? '',
    keycloak: parseKeycloak(o.keycloak),
    mode,
  };
}

/**
 * Loads `/config.json` (mounted from a ConfigMap in either chart). Missing or
 * malformed config falls back to the defaults so the SPA always boots.
 */
export async function loadConfig(url = '/config.json'): Promise<RuntimeConfig> {
  try {
    const response = await fetch(url, { cache: 'no-store' });
    current = response.ok ? parseConfig(await response.json()) : { ...DEFAULT_CONFIG };
  } catch {
    current = { ...DEFAULT_CONFIG };
  }
  return current;
}

export function getConfig(): RuntimeConfig {
  return current;
}

export function setConfig(config: Partial<RuntimeConfig>): void {
  current = { ...current, ...config };
}

export function resetConfig(): void {
  current = { ...DEFAULT_CONFIG };
}
