import { createKeycloakStrategy, type KeycloakFactory } from '@/auth/keycloak';
import { noAuthStrategy, setAuthStrategy, type AuthStrategy } from '@/auth/strategy';
import { type Capabilities, detectCapabilities, setCapabilities } from '@/capabilities';
import { getConfig } from '@/config';

export interface BootResult {
  capabilities: Capabilities;
  /** false → keycloak-js is redirecting to the login page; don't render. */
  ready: boolean;
}

/**
 * Startup after `/config.json` (and the MSW worker in mock mode): detect the backend, then pick
 * the auth strategy. Posture keeps the default gateway-cookie strategy. Provenance uses
 * keycloak-js PKCE when `/config.json` carries `keycloak.{url,realm,clientId}`, otherwise no auth
 * (the Go dashboard with OIDC disabled). `mockStrategy` replaces Keycloak in `VITE_API_MOCK=provenance`.
 */
export async function initBackend(
  options: { fetchImpl?: typeof fetch; keycloakFactory?: KeycloakFactory; mockStrategy?: AuthStrategy } = {},
): Promise<BootResult> {
  const capabilities = await detectCapabilities(options.fetchImpl);
  setCapabilities(capabilities);
  if (capabilities.mode !== 'provenance') return { capabilities, ready: true };
  if (options.mockStrategy) {
    setAuthStrategy(options.mockStrategy);
    return { capabilities, ready: true };
  }
  const { keycloak } = getConfig();
  if (!keycloak) {
    setAuthStrategy(noAuthStrategy);
    return { capabilities, ready: true };
  }
  const strategy = await createKeycloakStrategy(keycloak, { factory: options.keycloakFactory });
  setAuthStrategy(strategy);
  return { capabilities, ready: strategy.authenticated };
}
