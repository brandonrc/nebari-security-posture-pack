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
    renderApp('/compliance?tab=stig');
    expect(await screen.findByText('CAT I open')).toBeInTheDocument();
    const table = await screen.findByRole('table', { name: 'STIG rules' });
    await waitFor(() => expect(within(table).getAllByText('Not reviewed').length).toBeGreaterThan(0));
    expect(within(table).getAllByText('Open').length).toBeGreaterThan(0);
  });

  it('defaults to the Controls tab with family rollup and catalog', async () => {
    renderApp('/compliance');
    expect(await screen.findByRole('tab', { name: /Controls/, selected: true })).toBeInTheDocument();
    const chart = await screen.findByRole('list', { name: 'Control status by family' });
    await waitFor(() => expect(within(chart).getAllByRole('listitem').length).toBeGreaterThanOrEqual(8));
    const table = screen.getByRole('table', { name: 'Control catalog' });
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBeGreaterThan(20));
    expect(within(table).getAllByText(/^partial$/i).length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: /Run assertions/ })).toBeEnabled();
  });

  it('filters the catalog by family from the URL', async () => {
    renderApp('/compliance?family=SR');
    const table = await screen.findByRole('table', { name: 'Control catalog' });
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBeGreaterThan(2));
    const ids = within(table).getAllByRole('row').slice(1).map((r) => r.getAttribute('data-control'));
    expect(ids.every((id) => id?.startsWith('SR-'))).toBe(true);
  });

  it('offers OSCAL SSP / component definition and the compliance package', async () => {
    renderApp('/reports');
    expect(await screen.findByRole('button', { name: /Compliance package/ })).toBeInTheDocument();
  });

  it('lists reports in done/running/failed states', async () => {
    renderApp('/reports');
    const table = await screen.findByRole('table', { name: 'Reports' });
    await waitFor(() => expect(within(table).getAllByText('done').length).toBeGreaterThan(0));
    expect(within(table).getByText('failed')).toBeInTheDocument();
    expect(within(table).getByText('running')).toBeInTheDocument();
  });
});

describe('Supply chain', () => {
  it('renders stat tiles, Helm releases and unsigned/outdated lists', async () => {
    renderApp('/supply-chain');
    expect(await screen.findByText('Supply-chain score')).toBeInTheDocument();
    expect(screen.getByText('Helm releases with updates')).toBeInTheDocument();
    const helm = await screen.findByRole('table', { name: 'Helm releases' });
    await waitFor(() => expect(within(helm).getByText('keycloakx')).toBeInTheDocument());
    const outdated = await screen.findByRole('table', { name: 'Outdated images' });
    await waitFor(() => expect(within(outdated).getAllByRole('row').length).toBeGreaterThan(5));
    expect(within(outdated).getAllByLabelText(/^major update available/).length).toBeGreaterThan(0);
    expect(within(await screen.findByRole('table', { name: 'Unsigned images' })).getAllByLabelText('Signature: unsigned').length).toBeGreaterThan(0);
  });

  it('shows signed / SBOM / provenance glyphs and update chips on the images table', async () => {
    renderApp('/images');
    const table = await screen.findByRole('table', { name: 'Images' });
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBeGreaterThan(20));
    expect(within(table).getAllByLabelText('Signature: signed and verified').length).toBeGreaterThan(0);
    expect(within(table).getAllByLabelText('Signature: signed, not verified').length).toBeGreaterThan(0);
    expect(within(table).getAllByLabelText(/^SBOM: (spdx|cyclonedx)/).length).toBeGreaterThan(0);
    expect(within(table).getAllByLabelText('Provenance: not checked').length).toBe(1);
    expect(within(table).getAllByLabelText(/^(major|minor|patch) update available/).length).toBeGreaterThan(0);
  });

  it('itemises the supply-chain score on the image detail tab', async () => {
    renderApp('/images/img-004?tab=supply-chain');
    const deductions = await screen.findByRole('table', { name: 'Supply-chain score deductions' });
    expect(within(deductions).getByText('Signature present but not verified')).toBeInTheDocument();
    expect(within(deductions).getByText(/Major version behind/)).toBeInTheDocument();
    expect(screen.getByText(/none of the expected identities matched/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Download/ })).toHaveAttribute('href', '/api/v1/images/img-004/sbom');
  });

  it('degrades when the API has no provenance', async () => {
    server.use(
      http.get('*/api/v1/images/:id', ({ params }) =>
        HttpResponse.json({ id: params.id, ref: 'x/y:1', registry: 'x', repository: 'y', tag: '1', digest: null, score: 90, grade: 'A', counts: { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0 }, fixable: {}, scanners: {}, agreementIndex: null, namespaces: [], workloads: 0, containers: 0, running: true, lastScannedAt: null, mirrored: true, warnings: [], findings: [], usedBy: [], scans: [], postureFindings: [] }),
      ),
    );
    renderApp('/images/img-001?tab=supply-chain');
    expect(await screen.findByText('No supply-chain data')).toBeInTheDocument();
  });
});

describe('Overview §12/§13 tiles', () => {
  it('shows the 0.6/0.25/0.15 split, supply-chain and controls tiles', async () => {
    renderApp('/');
    expect(await screen.findByText('Vulnerability (×0.6)')).toBeInTheDocument();
    expect(screen.getByText('Configuration (×0.25)')).toBeInTheDocument();
    expect(screen.getByText('Supply chain (×0.15)')).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: /Controls implemented \d+ of \d+ \(moderate baseline\)/ })).toHaveAttribute('href', '/compliance');
    expect(await screen.findByRole('link', { name: /Details/ })).toHaveAttribute('href', '/supply-chain');
  });
});
