/**
 * Auth-strategy plug for `src/api/client.ts`, the single fetch layer.
 *
 * - `cookieStrategy` (posture mode, default): the Nebari gateway owns the session; requests carry
 *   the `NebariIdToken` / `IdToken*` cookies (`credentials: same-origin`), sign-out is `/logout`.
 * - a bearer strategy (provenance mode, `src/auth/keycloak.ts`): keycloak-js mints the token in the
 *   browser and every request carries `Authorization: Bearer …`.
 */
export interface AuthUser {
  name: string;
  email: string;
}

export interface AuthStrategy {
  readonly kind: 'cookie' | 'bearer' | 'none';
  /** Headers for the next request; `forceRefresh` after a 401 (the token was just rejected). */
  headers(forceRefresh?: boolean): Promise<Record<string, string>>;
  /** Retry once with `headers(true)` on a 401. */
  readonly retryOn401: boolean;
  signOut(): void;
  /** Identity from the ID token, when the strategy has one. */
  user(): AuthUser | null;
}

export const cookieStrategy: AuthStrategy = {
  kind: 'cookie',
  headers: async () => ({}),
  retryOn401: false,
  signOut: () => window.location.assign('/logout'),
  user: () => null,
};

/** Provenance mode without Keycloak config: the dashboard runs with auth disabled. */
export const noAuthStrategy: AuthStrategy = {
  kind: 'none',
  headers: async () => ({}),
  retryOn401: false,
  signOut: () => window.location.assign('/'),
  user: () => null,
};

let current: AuthStrategy = cookieStrategy;

export function getAuthStrategy(): AuthStrategy {
  return current;
}

export function setAuthStrategy(strategy: AuthStrategy): void {
  current = strategy;
}

export function resetAuthStrategy(): void {
  current = cookieStrategy;
}
