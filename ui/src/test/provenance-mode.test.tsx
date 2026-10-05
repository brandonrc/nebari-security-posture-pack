import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http } from 'msw';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SCAN_POLL } from '@/api/provenance-queries';
import { mockScan } from '@/mocks/provenance-backend';
import { server } from '@/mocks/server';
import { renderProvenanceApp } from './render';

const nav = () => screen.findByRole('navigation', { name: 'Security Posture sections' });

function setMockAuth(mode: string | null) {
  window.history.replaceState(null, '', mode ? `/?mockAuth=${mode}` : '/');
}

afterEach(() => setMockAuth(null));

describe('provenance-only mode: navigation and gating', () => {
  it('shows only the supply-chain sections in the sidebar and the provenance title', async () => {
    renderProvenanceApp('/');
    const sidebar = await nav();
    const labels = within(sidebar)
      .getAllByRole('link')
      .map((a) => a.textContent);
    expect(labels).toEqual(['Overview', 'Images', 'Supply chain', 'Reports', 'Scans']);
    expect(within(sidebar).getByText('Supply-chain provenance')).toBeInTheDocument();
    expect(within(sidebar).queryByText('Settings')).toBeNull();
  });

  it.each(['/settings', '/vulnerabilities', '/vulnerabilities/CVE-2024-1', '/workloads', '/namespaces', '/checks', '/checks/privileged', '/compliance', '/scans/12'])(
    '%s redirects to the Overview',
    async (path) => {
      renderProvenanceApp(path);
      expect(await screen.findByRole('heading', { level: 1, name: 'Overview' })).toBeInTheDocument();
      expect(await screen.findByText(/from the provenance collector/)).toBeInTheDocument();
    },
  );
});

describe('provenance-only mode: pages', () => {
  it('Overview: supply-chain score, stat tiles, report metadata, warnings and recent reports', async () => {
    renderProvenanceApp('/');
    expect(await screen.findByText('golden')).toBeInTheDocument();
    expect(screen.getByText('v0.0.0-golden')).toBeInTheDocument();
    expect(screen.getByText('1.1.0')).toBeInTheDocument();
    expect(screen.getByText('The collector reported 2 problems')).toBeInTheDocument();
    expect(within(screen.getByRole('list', { name: 'Report warnings' })).getAllByRole('listitem')).toHaveLength(2);
    expect(within(screen.getByLabelText('Namespaces scanned')).getAllByRole('link').map((a) => a.textContent)).toEqual(['default', 'kube-system', 'monitoring']);
    expect(screen.getByText('Signed').closest('[data-slot="card"]')).toHaveTextContent('2 of 5 images');
    expect(screen.getAllByText(/45\.8/).length).toBeGreaterThan(0);
    await waitFor(() => expect(within(screen.getByRole('list', { name: 'Recent reports' })).getAllByRole('listitem')).toHaveLength(3));
    expect(await screen.findByRole('button', { name: /Run scan/ })).toBeInTheDocument();
    // no posture tiles
    expect(screen.queryByText(/Scanner health|Top risks/i)).toBeNull();
  });

  it('Images: provenance columns only, client-side filters, links to the supply-chain tab', async () => {
    const user = userEvent.setup();
    renderProvenanceApp('/images');
    const table = await screen.findByRole('table', { name: 'Images' });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(6));
    const heads = within(table)
      .getAllByRole('columnheader')
      .map((h) => h.textContent?.trim());
    expect(heads).toEqual(expect.arrayContaining(['Image', 'Supply chain', 'Signed', 'SBOM', 'Provenance', 'Update', 'Namespaces', 'Workloads']));
    expect(heads.join(' ')).not.toMatch(/Findings|Scanners|Agreement|Last scanned/);
    expect(screen.queryByRole('combobox', { name: 'Severity' })).toBeNull();
    const link = within(table).getByRole('link', { name: 'ghcr.io/example/web:1.4.2' });
    expect(link).toHaveAttribute('href', '/images/ghcr.io%2Fexample%2Fweb%3A1.4.2?tab=supply-chain');

    await user.type(screen.getByRole('searchbox', { name: 'Search images' }), 'busybox');
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(2));
  });

  it('Image detail: used-by and supply-chain tabs from the report', async () => {
    const user = userEvent.setup();
    renderProvenanceApp('/images/busybox%3A1.36');
    expect(await screen.findByRole('heading', { level: 1, name: 'busybox' })).toBeInTheDocument();
    const tabs = screen.getByRole('tablist', { name: 'Image detail sections' });
    expect(within(tabs).getAllByRole('tab').map((t) => t.textContent?.replace(/\d+$/, '').trim())).toEqual(['Used by', expect.stringMatching(/^Supply chain/)]);
    expect(screen.queryByRole('button', { name: /Rescan image/ })).toBeNull();
    expect((await screen.findAllByText(/No SBOM attestation/)).length).toBeGreaterThan(0);
    await user.click(within(tabs).getByRole('tab', { name: /Used by/ }));
    const used = await screen.findByRole('table', { name: 'Containers using this image' });
    expect(within(used).getByText('web-7d9f')).toBeInTheDocument();
    expect(within(used).getByText('prometheus')).toBeInTheDocument();
  });

  it('Image detail: an image missing from the report is a 404', async () => {
    renderProvenanceApp('/images/nope%3A1');
    expect(await screen.findByText(/is not in this report/)).toBeInTheDocument();
  });

  it('Supply chain: tiles and Helm releases from the report', async () => {
    renderProvenanceApp('/supply-chain');
    const helm = await screen.findByRole('table', { name: 'Helm releases' });
    await waitFor(() => expect(within(helm).getAllByText('prometheus')).toHaveLength(2));
    expect(within(helm).getByText('failed')).toBeInTheDocument();
    expect(screen.getByText('Container-weighted mean of the per-image scores')).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'Unsigned images' })).toBeInTheDocument();
  });
});

describe('provenance-only mode: report history', () => {
  it('lists reports, switches the dataset with View, and goes back to latest', async () => {
    const user = userEvent.setup();
    renderProvenanceApp('/reports');
    const table = await screen.findByRole('table', { name: 'Reports' });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(4));
    expect(within(table).getByText('Latest · viewing')).toBeInTheDocument();
    // timelineDeltas is on in the mock /api/me: +1 unique image per run in the seed history
    await waitFor(() => expect(within(table).getByRole('columnheader', { name: 'Δ' })).toBeInTheDocument());
    expect(within(table).getAllByText('+1')).toHaveLength(2);

    await user.click(within(table).getByRole('button', { name: 'View report provenance-20261001-120000.json' }));
    expect(await screen.findByText('Viewing an earlier report')).toBeInTheDocument();

    await user.click(within(await nav()).getByRole('link', { name: 'Images' }));
    const images = await screen.findByRole('table', { name: 'Images' });
    await waitFor(() => expect(within(images).getAllByRole('row')).toHaveLength(4));
    expect(screen.getByText('Viewing an earlier report')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Back to latest' }));
    await waitFor(() => expect(within(images).getAllByRole('row')).toHaveLength(6));
    expect(screen.queryByText('Viewing an earlier report')).toBeNull();
  });

  it('downloads JSON and exports CSV / Markdown with the bearer', async () => {
    const user = userEvent.setup();
    const blobs: Blob[] = [];
    const names: string[] = [];
    const create = vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => {
      blobs.push(b as Blob);
      return `blob:${blobs.length}`;
    });
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      names.push(this.download);
    });
    try {
      renderProvenanceApp('/reports');
      await screen.findByRole('table', { name: 'Reports' });
      await user.click(screen.getByRole('button', { name: 'Export latest report as CSV' }));
      await waitFor(() => expect(names).toEqual(['provenance-report.csv']), { timeout: 5000 });
      expect(await blobs[0].text()).toMatch(/^Image,Namespace,Workload Kind/);
      await user.click(await screen.findByRole('button', { name: 'Export provenance-20261002-120000.json as Markdown' }));
      await waitFor(() => expect(names).toHaveLength(2), { timeout: 5000 });
      expect(await blobs[1].text()).toContain('# Provenance Report');
      await user.click(screen.getByRole('button', { name: 'Download provenance-20261002-120000.json as JSON' }));
      await waitFor(() => expect(names[2]).toBe('provenance-20261002-120000.json'), { timeout: 5000 });
      expect(JSON.parse(await blobs[2].text()).metadata.generatedAt).toBe('2026-10-02T12:00:00Z');
    } finally {
      create.mockRestore();
      revoke.mockRestore();
      click.mockRestore();
    }
  });

  it('a failed download toasts', async () => {
    const user = userEvent.setup();
    renderProvenanceApp('/reports');
    // after render: renderProvenanceApp's handlers are prepended, later server.use() wins
    server.use(http.get('*/api/export', () => new Response('report not found\n', { status: 404, headers: { 'Content-Type': 'text/plain' } })));
    await screen.findByRole('table', { name: 'Reports' });
    await user.click(screen.getByRole('button', { name: 'Export latest report as Markdown' }));
    expect((await screen.findAllByText('Download failed')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('404: report not found')).length).toBeGreaterThan(0);
  });
});

describe('provenance-only mode: Run scan', () => {
  const saved = { ...SCAN_POLL };
  beforeEach(() => {
    SCAN_POLL.intervalMs = 50;
    mockScan.durationMs = 150;
  });
  afterEach(() => {
    Object.assign(SCAN_POLL, saved);
    mockScan.durationMs = 8_000;
  });

  it('POSTs /api/scan, shows the job, polls /api/reports and adopts the new report', async () => {
    const user = userEvent.setup();
    renderProvenanceApp('/scans');
    const table = await screen.findByRole('table', { name: 'Scans' });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(4));
    await user.click(await screen.findByRole('button', { name: /Run scan/ }));
    expect((await screen.findAllByText('Scan started')).length).toBeGreaterThan(0);
    const status = await screen.findByLabelText('Scan job status');
    expect(status).toHaveTextContent('provenance/manual-');
    expect(screen.getByRole('button', { name: /Scan running/ })).toBeDisabled();
    expect((await screen.findAllByText('New report available', {}, { timeout: 5000 })).length).toBeGreaterThan(0);
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(5));
    expect(status).toHaveTextContent('→ provenance-');
    expect(screen.getByRole('button', { name: /Run scan/ })).toBeEnabled();
  });

  it('409 / 403 / 503 from /api/scan toast without locking the app', async () => {
    const user = userEvent.setup();
    const answer = { status: 409, body: 'a scan job is already active for this collector' };
    renderProvenanceApp('/scans');
    server.use(http.post('*/api/scan', () => new Response(`${answer.body}\n`, { status: answer.status, headers: { 'Content-Type': 'text/plain' } })));
    const run = await screen.findByRole('button', { name: /Run scan/ });
    await user.click(run);
    expect((await screen.findAllByText('A scan is already running')).length).toBeGreaterThan(0);
    answer.status = 403;
    answer.body = 'forbidden: caller is not in an admin group';
    await user.click(run);
    expect((await screen.findAllByText('Only members of the dashboard’s admin groups can run a scan.')).length).toBeGreaterThan(0);
    answer.status = 503;
    await user.click(run);
    expect((await screen.findAllByText(/Manual scans are not configured/)).length).toBeGreaterThan(0);
    expect(await nav()).toBeInTheDocument();
    expect(screen.queryByText(/restricted to members of an admin group/)).toBeNull();
  });

  it('is hidden for users without canRunScan; reads still work', async () => {
    setMockAuth('viewer');
    renderProvenanceApp('/scans');
    expect(await screen.findByText(/Manual scans are limited to the dashboard’s admin groups/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Run scan/ })).toBeNull();
    const table = await screen.findByRole('table', { name: 'Scans' });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(4));
  });
});

describe('provenance-only mode: auth', () => {
  it('a token the dashboard keeps rejecting (after a refresh) shows Session expired', async () => {
    setMockAuth('401');
    renderProvenanceApp('/reports');
    expect(await screen.findByText('Session expired')).toBeInTheDocument();
  });

  it('the profile menu shows the Keycloak identity and signs out through Keycloak', async () => {
    const user = userEvent.setup();
    const { keycloak } = renderProvenanceApp('/');
    const logout = vi.spyOn(keycloak, 'logout').mockResolvedValue();
    await user.click(await screen.findByRole('button', { name: 'Account menu' }));
    const groups = await screen.findByLabelText('Groups');
    expect(within(groups).getByText('admin')).toBeInTheDocument();
    expect(screen.getAllByText('Ada Admin').length).toBeGreaterThan(0);
    await user.click(screen.getByRole('menuitem', { name: /Sign out/ }));
    expect(logout).toHaveBeenCalledWith({ redirectUri: 'http://localhost:3000/' });
  });
});
