import { afterEach, describe, expect, it } from 'vitest';
import { server } from '@/mocks/server';
import { http, HttpResponse } from 'msw';
import { getConfig, loadConfig, parseConfig, resetConfig, setConfig } from '@/config';

describe('parseConfig', () => {
  it('accepts this pack’s keys', () => {
    expect(parseConfig({ apiBase: '/x/api/v1/', title: 'Posture', mode: 'posture', provenanceApiBase: '/pc/api/' })).toEqual({
      apiBase: '/x/api/v1',
      provenanceApiBase: '/pc/api',
      title: 'Posture',
      keycloak: null,
      mode: 'posture',
      branding: {},
    });
  });

  it('accepts provenance-collector-pack’s frontend-configmap shape (empty branding → defaults)', () => {
    const cfg = parseConfig({
      keycloak: { url: 'https://kc.example.com/', realm: 'nebari', clientId: 'provenance-provenance-collector-spa' },
      title: '',
      logoUrl: '',
      logoUrlDark: '',
      faviconUrl: '',
      theme: {},
    });
    expect(cfg).toEqual({
      apiBase: '/api/v1',
      provenanceApiBase: '/api',
      title: '',
      keycloak: { url: 'https://kc.example.com', realm: 'nebari', clientId: 'provenance-provenance-collector-spa' },
      mode: 'auto',
      branding: {},
    });
  });

  it('drops an incomplete keycloak block and junk values', () => {
    expect(parseConfig({ keycloak: { url: 'https://kc', realm: '', clientId: 'x' }, apiBase: 3, mode: 'other' })).toMatchObject({
      keycloak: null,
      apiBase: '/api/v1',
      mode: 'auto',
    });
    expect(parseConfig(null).apiBase).toBe('/api/v1');
    expect(parseConfig({ keycloak: 'nope' }).keycloak).toBeNull();
  });
});

describe('loadConfig', () => {
  const saved = getConfig();
  afterEach(() => setConfig(saved));

  it('reads /config.json and falls back to defaults on errors', async () => {
    server.use(http.get('*/config.json', () => HttpResponse.json({ keycloak: { url: 'https://kc', realm: 'r', clientId: 'c' } })));
    expect((await loadConfig('http://localhost/config.json')).keycloak).toEqual({ url: 'https://kc', realm: 'r', clientId: 'c' });
    server.use(http.get('*/config.json', () => new HttpResponse('nope', { status: 404 })));
    expect((await loadConfig('http://localhost/config.json')).keycloak).toBeNull();
    server.use(http.get('*/config.json', () => HttpResponse.error()));
    expect((await loadConfig('http://localhost/config.json')).apiBase).toBe('/api/v1');
    resetConfig();
    expect(getConfig().mode).toBe('auto');
  });
});
