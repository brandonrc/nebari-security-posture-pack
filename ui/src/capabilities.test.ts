import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { capabilitiesFor, detectCapabilities, getCapabilities, isProvenanceMode, productTitle, setCapabilities, useCapabilities } from '@/capabilities';
import { getConfig, setConfig } from '@/config';

const respond = (status: number, contentType = 'application/json') =>
  vi.fn(async () => new Response(status === 204 ? null : '{}', { status, headers: { 'content-type': contentType } }));

describe('detectCapabilities', () => {
  const saved = getConfig();
  afterEach(() => setConfig(saved));

  it.each([200, 401, 403, 500, 502])('HTTP %i from /summary → posture', async (status) => {
    const probe = respond(status);
    expect((await detectCapabilities(probe)).mode).toBe('posture');
    expect(probe).toHaveBeenCalledWith('http://localhost/api/v1/summary', expect.objectContaining({ credentials: 'same-origin' }));
  });

  it('404 → provenance-only', async () => {
    expect((await detectCapabilities(respond(404, 'text/plain'))).mode).toBe('provenance');
  });

  it('a network error → provenance-only', async () => {
    const probe = vi.fn(async () => {
      throw new TypeError('Failed to fetch');
    });
    expect((await detectCapabilities(probe)).mode).toBe('provenance');
  });

  it('an HTML 200 (static SPA fallback, no API behind /api/v1) → provenance-only', async () => {
    expect((await detectCapabilities(respond(200, 'text/html; charset=utf-8'))).mode).toBe('provenance');
  });

  it('`mode` in /config.json skips the probe', async () => {
    const probe = respond(200);
    setConfig({ mode: 'provenance' });
    expect((await detectCapabilities(probe)).mode).toBe('provenance');
    setConfig({ mode: 'posture' });
    expect((await detectCapabilities(probe)).mode).toBe('posture');
    expect(probe).not.toHaveBeenCalled();
  });

  it('probes through MSW against the posture mock', async () => {
    expect((await detectCapabilities()).mode).toBe('posture');
  });
});

describe('capabilities store', () => {
  it('provenance mode exposes only the supply-chain subset', () => {
    const { features } = capabilitiesFor('provenance');
    expect(Object.entries(features).filter(([, on]) => on).map(([f]) => f).sort()).toEqual(
      ['helmReleases', 'images', 'overview', 'reports', 'scans', 'supplyChain'].sort(),
    );
    expect(Object.values(capabilitiesFor('posture').features).every(Boolean)).toBe(true);
  });

  it('useCapabilities re-renders on change; productTitle follows mode unless configured', () => {
    const { result } = renderHook(() => useCapabilities());
    expect(result.current.mode).toBe('posture');
    expect(productTitle()).toBe('Security Posture');
    act(() => setCapabilities('provenance'));
    expect(result.current.mode).toBe('provenance');
    expect(isProvenanceMode()).toBe(true);
    expect(getCapabilities().features.settings).toBe(false);
    expect(productTitle()).toBe('Supply-chain provenance');
    setConfig({ title: 'Provenance Dashboard' });
    expect(productTitle()).toBe('Provenance Dashboard');
    setConfig({ title: '' });
  });
});
