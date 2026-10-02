export interface RuntimeConfig {
  apiBase: string;
  title: string;
}

const DEFAULT_CONFIG: RuntimeConfig = {
  apiBase: '/api/v1',
  title: 'Security Posture',
};

let current: RuntimeConfig = { ...DEFAULT_CONFIG };

/**
 * Loads `/config.json` (mounted from a ConfigMap in the chart). Missing or
 * malformed config falls back to the defaults so the SPA always boots.
 */
export async function loadConfig(): Promise<RuntimeConfig> {
  try {
    const response = await fetch('/config.json', { cache: 'no-store' });
    if (response.ok) {
      const data = (await response.json()) as Partial<RuntimeConfig>;
      current = {
        apiBase: typeof data.apiBase === 'string' && data.apiBase ? data.apiBase.replace(/\/$/, '') : DEFAULT_CONFIG.apiBase,
        title: typeof data.title === 'string' && data.title ? data.title : DEFAULT_CONFIG.title,
      };
    }
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
