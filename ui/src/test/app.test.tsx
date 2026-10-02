import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { server } from '@/mocks/server';
import { renderApp } from './render';

describe('Overview', () => {
  it('renders grade, severity tiles, scanners and top risks from /summary', async () => {
    renderApp('/');
    expect(await screen.findByText('Cluster security posture')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /Score .* of 100, grade [A-F]/ })).toBeInTheDocument();
    for (const name of ['Trivy', 'Grype', 'Clair']) expect(screen.getAllByText(name).length).toBeGreaterThan(0);
    expect(screen.getByRole('table', { name: 'Top 10 riskiest images' })).toBeInTheDocument();
    expect(screen.getByText(/grype database is \d+ days old/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Scan now/ })).toBeEnabled();
  });

  it('shows the profile menu with groups and a menuitemradio theme picker', async () => {
    const user = userEvent.setup();
    renderApp('/');
    const trigger = await screen.findByRole('button', { name: 'Account menu' });
    await user.click(trigger);
    const menu = await screen.findByRole('menu');
    expect(within(menu).getByText('admin@nebari.example')).toBeInTheDocument();
    const radios = within(menu).getAllByRole('menuitemradio');
    expect(radios).toHaveLength(3);
    expect(radios.find((r) => r.getAttribute('aria-checked') === 'true')).toHaveAccessibleName('System mode');
    expect(within(menu).getByRole('menuitem', { name: /Sign out/ })).toBeInTheDocument();
  });
});

describe('Images', () => {
  it('lists images with grade, scanner glyphs and supports the text filter', async () => {
    const user = userEvent.setup();
    renderApp('/images');
    const table = await screen.findByRole('table', { name: 'Images' });
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBeGreaterThan(20));
    expect(within(table).getAllByLabelText(/Clair: (unsupported|timeout|error)/).length).toBeGreaterThan(0);
    await user.type(screen.getByRole('searchbox', { name: 'Search images' }), 'keycloak');
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(2), { timeout: 4000 });
    expect(within(table).getByText('quay.io/keycloak/keycloak:26.0.5')).toBeInTheDocument();
  });
});

describe('Image detail', () => {
  it('shows the three-scanner findings table', async () => {
    renderApp('/images/img-003');
    const table = await screen.findByRole('table', { name: 'Findings' });
    for (const name of ['Trivy', 'Grype', 'Clair']) expect(within(table).getByRole('columnheader', { name })).toBeInTheDocument();
    expect(table.querySelectorAll('[data-agree]').length).toBeGreaterThan(0);
  });
});

describe('Auth states', () => {
  it('renders Session expired on 401', async () => {
    server.use(http.get('*/api/v1/*', () => HttpResponse.json({ detail: 'not authenticated' }, { status: 401 })));
    renderApp('/');
    expect(await screen.findByRole('heading', { name: 'Session expired' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Sign in/ })).toBeInTheDocument();
  });

  it('renders Admins only on 403', async () => {
    server.use(http.get('*/api/v1/*', () => HttpResponse.json({ detail: 'admin group required' }, { status: 403 })));
    renderApp('/images');
    expect(await screen.findByRole('heading', { name: 'Admins only' })).toBeInTheDocument();
  });
});

describe('Compliance & reports', () => {
  it('renders STIG CAT tiles and rule statuses', async () => {
    renderApp('/compliance');
    expect(await screen.findByText('CAT I open')).toBeInTheDocument();
    const table = await screen.findByRole('table', { name: 'STIG rules' });
    await waitFor(() => expect(within(table).getAllByText('Not reviewed').length).toBeGreaterThan(0));
    expect(within(table).getAllByText('Open').length).toBeGreaterThan(0);
  });

  it('lists reports in done/running/failed states', async () => {
    renderApp('/reports');
    const table = await screen.findByRole('table', { name: 'Reports' });
    await waitFor(() => expect(within(table).getAllByText('done').length).toBeGreaterThan(0));
    expect(within(table).getByText('failed')).toBeInTheDocument();
    expect(within(table).getByText('running')).toBeInTheDocument();
  });
});
