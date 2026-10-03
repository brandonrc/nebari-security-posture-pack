import { screen, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { me } from '@/mocks/fixtures';
import { server } from '@/mocks/server';
import { renderApp } from './render';

/**
 * Quality review M5: every route, against contract-violating API bodies (what a rolling upgrade
 * can briefly serve). No combination may fall through to React Router's "Unexpected Application
 * Error" screen, and with the defensive defaults in src/api/normalize.ts none may need the route
 * error card either: every page renders its empty state.
 */
const ROUTES = [
  '/',
  '/images',
  '/images/img-001',
  '/vulnerabilities',
  '/vulnerabilities/CVE-2024-0001',
  '/workloads',
  '/namespaces',
  '/checks',
  '/checks/privileged',
  '/supply-chain',
  '/scans',
  '/scans/1',
  '/reports',
  '/compliance',
  '/settings',
  '/no-such-page',
] as const;

const BODIES: Array<[string, unknown]> = [
  ['{}', {}],
  ['[]', []],
  ['null', null],
  ['{items:null}', { items: null }],
];

beforeEach(() => {
  // React logs caught render errors; keep the output readable
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

describe.each(BODIES)('every route survives a %s API body', (_label, body) => {
  it.each(ROUTES)('%s', async (path) => {
    server.use(
      http.get('*/api/v1/me', () => HttpResponse.json(me)),
      http.get('*/api/v1/*', () => HttpResponse.json(body as never)),
    );
    renderApp(path);
    // the app shell (sidebar) is up, i.e. the root did not fail
    expect(await screen.findByRole('navigation', { name: 'Security Posture sections' }, { timeout: 5000 })).toBeInTheDocument();
    // give queries a chance to settle and render their (bad) data
    await waitFor(() => expect(document.querySelector('[aria-busy="true"]')).toBeNull(), { timeout: 5000 }).catch(() => {});
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByText(/Unexpected Application Error/i)).toBeNull();
    expect(screen.queryByText('Security Posture failed to load')).toBeNull();
    expect(screen.queryByText('This page failed to load')).toBeNull();
  });
});
