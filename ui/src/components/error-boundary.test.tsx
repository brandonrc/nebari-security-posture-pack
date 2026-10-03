import { QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createQueryClient } from '@/query-client';
import { describeError, RootErrorBoundary, RouteErrorBoundary } from './error-boundary';

let broken = true;

function Flaky() {
  if (broken) throw new TypeError("Cannot read properties of undefined (reading 'trivy')");
  return <p>page content</p>;
}

function setup(errorElement = <RouteErrorBoundary />) {
  const router = createMemoryRouter(
    [{ path: '/', element: <nav aria-label="shell">shell</nav>, children: [] }, { path: '/page', element: <Flaky />, errorElement }],
    { initialEntries: ['/page'] },
  );
  const client = createQueryClient();
  const resetQueries = vi.spyOn(client, 'resetQueries');
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { router, resetQueries };
}

beforeEach(() => {
  broken = true;
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

describe('RouteErrorBoundary', () => {
  it('shows a compact error card instead of the router default screen', async () => {
    setup();
    const card = await screen.findByRole('alert', { name: 'This page failed to load' });
    expect(card).toHaveTextContent("reading 'trivy'");
    expect(screen.queryByText(/Unexpected Application Error/)).toBeNull();
    expect(screen.getByRole('link', { name: /Overview/ })).toHaveAttribute('href', '/');
  });

  it('retry refetches and re-renders the page once it works', async () => {
    const user = userEvent.setup();
    const { router, resetQueries } = setup();
    await screen.findByRole('alert');
    broken = false;
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('page content')).toBeInTheDocument();
    expect(resetQueries).toHaveBeenCalled();
    expect(router.state.location.pathname).toBe('/page');
  });

  it('keeps showing the card when the page still fails', async () => {
    const user = userEvent.setup();
    setup();
    await screen.findByRole('alert');
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('alert', { name: 'This page failed to load' })).toBeInTheDocument();
  });
});

describe('RootErrorBoundary', () => {
  it('reloads the whole app on retry and offers no in-app link', async () => {
    const reload = vi.fn();
    vi.stubGlobal('location', { ...window.location, reload });
    const user = userEvent.setup();
    setup(<RootErrorBoundary />);
    await screen.findByRole('alert', { name: 'Security Posture failed to load' });
    expect(screen.queryByRole('link', { name: /Overview/ })).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(reload).toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
});

describe('describeError', () => {
  it('formats every kind of thrown value', () => {
    expect(describeError(new Error('boom'))).toBe('boom');
    expect(describeError(new RangeError(''))).toBe('RangeError');
    expect(describeError('plain')).toBe('plain');
    expect(describeError({ status: 1 })).toBe('{"status":1}');
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(describeError(cyclic)).toBe('Unknown error');
    expect(describeError(undefined)).toBe('Unknown error');
  });
});
