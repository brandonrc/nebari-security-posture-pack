import Keycloak, { type KeycloakConfig as KcConfig, type KeycloakInitOptions } from 'keycloak-js';
import type { KeycloakConfig } from '@/config';
import type { AuthStrategy, AuthUser } from './strategy';

/**
 * keycloak-js PKCE login for provenance mode, matching provenance-collector-pack's old
 * `frontend/src/auth/keycloak.ts`: `login-required` + `S256`, no session iframe; the access token
 * is sent as a bearer on every API call and refreshed when it has < 30 s left. The dashboard
 * validates it against Keycloak's userinfo endpoint.
 */

/** The subset of a keycloak-js instance this module uses (tests pass a fake). */
export interface KeycloakLike {
  authenticated?: boolean;
  token?: string;
  idTokenParsed?: Record<string, unknown>;
  init(options: KeycloakInitOptions): Promise<boolean>;
  updateToken(minValidity: number): Promise<boolean>;
  login(options?: { redirectUri?: string }): Promise<void>;
  logout(options?: { redirectUri?: string }): Promise<void>;
}

export type KeycloakFactory = (config: KcConfig) => KeycloakLike;

/** Thrown when the session can't be refreshed; a redirect to Keycloak is already in flight. */
export class SessionExpiredError extends Error {
  constructor() {
    super('Session expired — redirecting to login');
    this.name = 'SessionExpiredError';
  }
}

export const KEYCLOAK_INIT_OPTIONS: KeycloakInitOptions = {
  onLoad: 'login-required',
  pkceMethod: 'S256',
  checkLoginIframe: false,
};

export interface KeycloakStrategy extends AuthStrategy {
  readonly keycloak: KeycloakLike;
  /** false → keycloak-js is redirecting the browser to the login page; don't render. */
  readonly authenticated: boolean;
}

function userFrom(kc: KeycloakLike): AuthUser | null {
  const claims = kc.idTokenParsed;
  if (!kc.authenticated || !claims) return null;
  const s = (k: string) => (typeof claims[k] === 'string' ? (claims[k] as string) : '');
  return { name: s('name') || s('preferred_username') || s('email') || s('sub') || 'User', email: s('email') };
}

/** Wraps an initialised keycloak-js instance as the client's bearer strategy. */
export function bearerStrategy(kc: KeycloakLike, authenticated = Boolean(kc.authenticated)): KeycloakStrategy {
  const relogin = () => {
    void kc.login();
    return new SessionExpiredError();
  };
  return {
    kind: 'bearer',
    keycloak: kc,
    authenticated,
    retryOn401: true,
    async headers(forceRefresh = false) {
      if (!kc.authenticated) throw relogin();
      try {
        // -1 forces a refresh (the token was just rejected); 30 is a no-op unless < 30 s remain
        await kc.updateToken(forceRefresh ? -1 : 30);
      } catch {
        throw relogin();
      }
      if (!kc.token) throw relogin();
      return { Authorization: `Bearer ${kc.token}` };
    },
    signOut() {
      void kc.logout({ redirectUri: `${window.location.origin}/` });
    },
    user: () => userFrom(kc),
  };
}

/** Initialise keycloak-js from `/config.json`'s `keycloak` block. */
export async function createKeycloakStrategy(
  config: KeycloakConfig,
  options: { factory?: KeycloakFactory; initOptions?: Partial<KeycloakInitOptions> } = {},
): Promise<KeycloakStrategy> {
  const factory: KeycloakFactory = options.factory ?? ((c) => new Keycloak(c) as unknown as KeycloakLike);
  const kc = factory({ url: config.url, realm: config.realm, clientId: config.clientId });
  const authenticated = await kc.init({ ...KEYCLOAK_INIT_OPTIONS, ...options.initOptions });
  return bearerStrategy(kc, authenticated);
}

/**
 * A stand-in authenticated session (no Keycloak server): used by `VITE_API_MOCK=provenance`
 * and tests. Never wired into a production build.
 */
export function fakeKeycloak(token: string, claims: Record<string, unknown>): KeycloakLike {
  return {
    authenticated: true,
    token,
    idTokenParsed: claims,
    init: async () => true,
    updateToken: async () => false,
    login: async () => {},
    logout: async () => {
      window.location.assign('/');
    },
  };
}
