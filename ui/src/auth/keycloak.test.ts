import Keycloak, { type KeycloakAdapter } from 'keycloak-js';
import { http, HttpResponse } from 'msw';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { provenanceApi } from '@/api/client';
import { bearerStrategy, createKeycloakStrategy, fakeKeycloak, KEYCLOAK_INIT_OPTIONS, type KeycloakLike, SessionExpiredError } from '@/auth/keycloak';
import { cookieStrategy, getAuthStrategy, noAuthStrategy, setAuthStrategy } from '@/auth/strategy';
import { server } from '@/mocks/server';

/**
 * A fake Keycloak realm (authorization-code + PKCE S256): the test plays the browser redirect
 * dance, the real keycloak-js does the rest (challenge, callback parsing, code exchange, nonce
 * check, refresh). The dashboard stand-in only accepts the access token Keycloak minted.
 */
const KC = 'https://kc.example.com';
const REALM = 'nebari';
const CLIENT = 'provenance-provenance-collector-spa';
const OIDC = `${KC}/realms/${REALM}/protocol/openid-connect`;

const b64url = (input: Uint8Array | string) => {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const jwt = (claims: Record<string, unknown>) => `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify(claims))}.sig`;

interface Grant {
  challenge: string;
  method: string;
  nonce: string;
  redirectUri: string;
}

let grants: Map<string, Grant>;
let issued: string[];
let tokenRequests: URLSearchParams[];

function mint(nonce: string, n: number) {
  const now = Math.floor(Date.now() / 1000);
  const access = jwt({ sub: 'ada', exp: now + 300, iat: now, n });
  issued.push(access);
  return {
    access_token: access,
    refresh_token: jwt({ sub: 'ada', exp: now + 1800, iat: now, typ: 'Refresh' }),
    id_token: jwt({ sub: 'ada', exp: now + 300, iat: now, nonce, name: 'Ada Lovelace', email: 'ada@example.com', preferred_username: 'ada' }),
    token_type: 'Bearer',
    expires_in: 300,
  };
}

const keycloakServer = [
  http.post(`${OIDC}/token`, async ({ request }) => {
    const form = new URLSearchParams(await request.text());
    tokenRequests.push(form);
    if (form.get('client_id') !== CLIENT) return HttpResponse.json({ error: 'invalid_client' }, { status: 401 });
    if (form.get('grant_type') === 'refresh_token') return HttpResponse.json(mint('', issued.length));
    const grant = grants.get(form.get('code') ?? '');
    if (!grant || form.get('redirect_uri') !== grant.redirectUri) return HttpResponse.json({ error: 'invalid_grant' }, { status: 400 });
    const verifier = form.get('code_verifier') ?? '';
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
    if (grant.method !== 'S256' || b64url(digest) !== grant.challenge) return HttpResponse.json({ error: 'invalid_grant', error_description: 'PKCE verification failed' }, { status: 400 });
    grants.delete(form.get('code') ?? '');
    return HttpResponse.json(mint(grant.nonce, issued.length));
  }),
];

/** Dashboard stand-in: `GET /api/reports` only for the newest access token. */
const dashboard = [
  http.get('*/api/reports', ({ request }) =>
    request.headers.get('authorization') === `Bearer ${issued.at(-1)}` ? HttpResponse.json([]) : new HttpResponse('unauthorized\n', { status: 401 }),
  ),
];

function testAdapter(get: () => Keycloak, captured: { loginUrl?: string; logout?: string }): KeycloakAdapter {
  return {
    login: async (options) => {
      captured.loginUrl = await get().createLoginUrl(options);
    },
    logout: async (options) => {
      captured.logout = get().createLogoutUrl(options);
    },
    register: async () => {},
    accountManagement: async () => {},
    redirectUri: (options) => options?.redirectUri ?? window.location.href,
  };
}

describe('keycloak-js PKCE login against a fake Keycloak', () => {
  beforeEach(() => {
    grants = new Map();
    issued = [];
    tokenRequests = [];
    server.use(...keycloakServer, ...dashboard);
    localStorage.clear();
    window.history.replaceState(null, '', '/images?namespace=default');
  });
  afterEach(() => {
    window.history.replaceState(null, '', '/');
  });

  it('redirects with an S256 challenge, exchanges the code with its verifier, sends and refreshes the bearer', async () => {
    const config = { url: KC, realm: REALM, clientId: CLIENT };
    const captured: { loginUrl?: string; logout?: string } = {};
    let kc!: Keycloak;
    const factory = (c: ConstructorParameters<typeof Keycloak>[0]) => (kc = new Keycloak(c)) as unknown as KeycloakLike;

    // 1. first load: login-required → redirect to the authorization endpoint
    const first = await createKeycloakStrategy(config, { factory, initOptions: { adapter: testAdapter(() => kc, captured) } });
    expect(first.authenticated).toBe(false);
    const login = new URL(captured.loginUrl ?? '');
    expect(`${login.origin}${login.pathname}`).toBe(`${OIDC}/auth`);
    const q = login.searchParams;
    expect(q.get('client_id')).toBe(CLIENT);
    expect(q.get('response_type')).toBe('code');
    expect(q.get('code_challenge_method')).toBe('S256');
    expect(q.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(q.get('redirect_uri')).toBe('http://localhost:3000/images?namespace=default');
    expect(q.get('scope')).toContain('openid');

    // 2. Keycloak authenticates the user and redirects back with a code (fragment response mode)
    grants.set('code-1', { challenge: q.get('code_challenge') ?? '', method: q.get('code_challenge_method') ?? '', nonce: q.get('nonce') ?? '', redirectUri: q.get('redirect_uri') ?? '' });
    window.history.replaceState(null, '', `/images?namespace=default#state=${q.get('state')}&session_state=s1&code=code-1`);

    // 3. second load: keycloak-js finds the callback, POSTs code + code_verifier, checks the nonce
    const strategy = await createKeycloakStrategy(config, { factory, initOptions: { adapter: testAdapter(() => kc, captured) } });
    expect(strategy.authenticated).toBe(true);
    expect(tokenRequests[0].get('grant_type')).toBe('authorization_code');
    expect(tokenRequests[0].get('code_verifier')).toMatch(/^[A-Za-z0-9]{96}$/);
    expect(window.location.hash).toBe('');
    expect(window.location.pathname + window.location.search).toBe('/images?namespace=default');
    expect(strategy.user()).toEqual({ name: 'Ada Lovelace', email: 'ada@example.com' });

    // 4. every API call carries the bearer
    setAuthStrategy(strategy);
    await expect(provenanceApi.reports()).resolves.toEqual([]);
    expect(await strategy.headers()).toEqual({ Authorization: `Bearer ${issued[0]}` });

    // 5. the dashboard rejects a token → refresh (refresh_token grant) and retry once
    issued.push('rotated-elsewhere');
    await expect(provenanceApi.reports()).resolves.toEqual([]);
    expect(tokenRequests.at(-1)?.get('grant_type')).toBe('refresh_token');

    // 6. sign out → end-session endpoint, back to the app root
    strategy.signOut();
    await vi.waitFor(() => expect(captured.logout).toBeDefined());
    const logout = new URL(captured.logout ?? '');
    expect(logout.pathname).toBe(`/realms/${REALM}/protocol/openid-connect/logout`);
    expect(logout.searchParams.get('post_logout_redirect_uri')).toBe('http://localhost:3000/');
  });

  it('a tampered verifier fails the exchange (no session)', async () => {
    const config = { url: KC, realm: REALM, clientId: CLIENT };
    const captured: { loginUrl?: string } = {};
    let kc!: Keycloak;
    const factory = (c: ConstructorParameters<typeof Keycloak>[0]) => (kc = new Keycloak(c)) as unknown as KeycloakLike;
    await createKeycloakStrategy(config, { factory, initOptions: { adapter: testAdapter(() => kc, captured) } });
    const q = new URL(captured.loginUrl ?? '').searchParams;
    grants.set('code-2', { challenge: 'not-the-challenge', method: 'S256', nonce: q.get('nonce') ?? '', redirectUri: q.get('redirect_uri') ?? '' });
    window.history.replaceState(null, '', `/images?namespace=default#state=${q.get('state')}&code=code-2`);
    await expect(createKeycloakStrategy(config, { factory, initOptions: { adapter: testAdapter(() => kc, captured) } })).rejects.toBeDefined();
  });
});

describe('bearer strategy', () => {
  afterEach(() => setAuthStrategy(cookieStrategy));

  it('uses login-required + S256 without the session iframe by default', async () => {
    const init = vi.fn(async () => true);
    const kc = { ...fakeKeycloak('t', {}), init };
    const s = await createKeycloakStrategy({ url: KC, realm: REALM, clientId: CLIENT }, { factory: () => kc });
    expect(init).toHaveBeenCalledWith(KEYCLOAK_INIT_OPTIONS);
    expect(KEYCLOAK_INIT_OPTIONS).toEqual({ onLoad: 'login-required', pkceMethod: 'S256', checkLoginIframe: false });
    expect(s.authenticated).toBe(true);
  });

  it('refreshes within 30 s of expiry, forces a refresh after a 401, re-logs in when refresh fails', async () => {
    const kc = fakeKeycloak('tok', { preferred_username: 'ada' });
    const updateToken = vi.spyOn(kc, 'updateToken');
    const login = vi.spyOn(kc, 'login');
    const s = bearerStrategy(kc);
    expect(await s.headers()).toEqual({ Authorization: 'Bearer tok' });
    expect(updateToken).toHaveBeenLastCalledWith(30);
    await s.headers(true);
    expect(updateToken).toHaveBeenLastCalledWith(-1);
    expect(s.user()).toEqual({ name: 'ada', email: '' });

    updateToken.mockRejectedValueOnce(new Error('refresh expired'));
    await expect(s.headers()).rejects.toBeInstanceOf(SessionExpiredError);
    expect(login).toHaveBeenCalledTimes(1);

    kc.token = undefined;
    await expect(s.headers()).rejects.toBeInstanceOf(SessionExpiredError);
    kc.authenticated = false;
    await expect(s.headers()).rejects.toBeInstanceOf(SessionExpiredError);
    expect(s.user()).toBeNull();
    expect(login).toHaveBeenCalledTimes(3);
  });

  it('the client turns a failed refresh into a 401 ApiError', async () => {
    const kc = fakeKeycloak('tok', {});
    kc.authenticated = false;
    setAuthStrategy(bearerStrategy(kc));
    await expect(provenanceApi.reports()).rejects.toMatchObject({ status: 401 });
  });

  it('sign-out goes through Keycloak logout; cookie / no-auth strategies are header-less', async () => {
    const kc = fakeKeycloak('tok', {});
    const logout = vi.spyOn(kc, 'logout').mockResolvedValue();
    bearerStrategy(kc).signOut();
    expect(logout).toHaveBeenCalledWith({ redirectUri: 'http://localhost:3000/' });
    expect(await cookieStrategy.headers()).toEqual({});
    expect(await noAuthStrategy.headers()).toEqual({});
    expect(noAuthStrategy.user()).toBeNull();
    expect(getAuthStrategy()).toBe(cookieStrategy);
  });
});
