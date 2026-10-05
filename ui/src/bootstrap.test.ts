import { afterEach, describe, expect, it, vi } from 'vitest';
import { fakeKeycloak } from '@/auth/keycloak';
import { cookieStrategy, getAuthStrategy, noAuthStrategy } from '@/auth/strategy';
import { initBackend } from '@/bootstrap';
import { getCapabilities } from '@/capabilities';
import { getConfig, setConfig } from '@/config';

const notFound = vi.fn(async () => new Response('404 page not found', { status: 404 }));
const ok = vi.fn(async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));

describe('initBackend', () => {
  const saved = getConfig();
  afterEach(() => setConfig(saved));

  it('posture backend → cookie strategy, every feature', async () => {
    const r = await initBackend({ fetchImpl: ok });
    expect(r).toMatchObject({ ready: true, capabilities: { mode: 'posture' } });
    expect(getAuthStrategy()).toBe(cookieStrategy);
  });

  it('provenance backend without a keycloak block → unauthenticated dashboard', async () => {
    const r = await initBackend({ fetchImpl: notFound });
    expect(r.capabilities.mode).toBe('provenance');
    expect(getCapabilities().features.settings).toBe(false);
    expect(getAuthStrategy()).toBe(noAuthStrategy);
  });

  it('provenance backend with keycloak → PKCE login; not ready while redirecting', async () => {
    setConfig({ keycloak: { url: 'https://kc', realm: 'nebari', clientId: 'spa' } });
    const kc = fakeKeycloak('t', {});
    const factory = vi.fn(() => ({ ...kc, init: async () => false }));
    const r = await initBackend({ fetchImpl: notFound, keycloakFactory: factory });
    expect(factory).toHaveBeenCalledWith({ url: 'https://kc', realm: 'nebari', clientId: 'spa' });
    expect(r.ready).toBe(false);
    expect(getAuthStrategy().kind).toBe('bearer');

    const signedIn = await initBackend({ fetchImpl: notFound, keycloakFactory: () => kc });
    expect(signedIn.ready).toBe(true);
  });

  it('mock strategy wins in VITE_API_MOCK=provenance', async () => {
    const r = await initBackend({ fetchImpl: notFound, mockStrategy: noAuthStrategy });
    expect(r.ready).toBe(true);
    expect(getAuthStrategy()).toBe(noAuthStrategy);
  });
});
