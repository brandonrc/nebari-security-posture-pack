import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import type { AffectedImage, VulnDetail, VulnSummary } from '@/api/types';
import { server } from '@/mocks/server';
import { renderApp } from './render';

const vuln = (i: number, over: Partial<VulnSummary> = {}): VulnSummary => ({
  vulnId: `CVE-2025-${String(1000 + i)}`,
  severity: i % 2 ? 'high' : 'critical',
  scanners: i % 3 ? ['trivy', 'grype'] : ['trivy', 'grype', 'clair'],
  agreement: 0.67,
  imagesAffected: 3,
  workloadsAffected: 5,
  fixAvailable: i % 2 === 0,
  cvss: 9.1,
  title: `Issue ${i}`,
  url: i === 0 ? 'https://nvd.nist.gov/vuln/detail/CVE-2025-1000' : null,
  controls: ['SI-2'],
  ...over,
});

function serveList() {
  const requests: URLSearchParams[] = [];
  const all = Array.from({ length: 120 }, (_, i) => vuln(i));
  server.use(
    http.get('*/api/v1/vulnerabilities', ({ request }) => {
      const p = new URL(request.url).searchParams;
      requests.push(p);
      let items = all;
      const q = p.get('q');
      if (q) items = items.filter((v) => v.vulnId.includes(q));
      if (p.get('fixable') === 'true') items = items.filter((v) => v.fixAvailable);
      if (p.get('severity')) items = items.filter((v) => v.severity === p.get('severity'));
      const page = Number(p.get('page') ?? 1);
      const size = Number(p.get('pageSize') ?? 50);
      return HttpResponse.json({ items: items.slice((page - 1) * size, page * size), total: items.length, page, pageSize: size });
    }),
  );
  return requests;
}

const bodyRows = () => within(screen.getByRole('table', { name: 'Vulnerabilities' })).getAllByRole('row').slice(1);

describe('Vulnerabilities page', () => {
  it('lists CVEs with severity, scanners, reach, fix and advisory link', async () => {
    serveList();
    renderApp('/vulnerabilities');
    await waitFor(() => expect(bodyRows()).toHaveLength(50));
    const first = bodyRows()[0];
    expect(within(first).getByRole('link', { name: 'CVE-2025-1000' })).toHaveAttribute('href', '/vulnerabilities/CVE-2025-1000');
    expect(within(first).getByText('fix available')).toBeInTheDocument();
    expect(within(first).getByText('9.1')).toBeInTheDocument();
    expect(within(first).getByRole('link', { name: /NVD/ })).toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2025-1000');
    expect(within(first).getByTitle('Clair: reported')).toBeInTheDocument();
    expect(within(bodyRows()[1]).getByTitle('Clair: not reported')).toBeInTheDocument();
    expect(within(bodyRows()[1]).getByText('no fix')).toBeInTheDocument();
  });

  it('pages, searches (debounced) and toggles fix-available through query params', async () => {
    const user = userEvent.setup({ delay: null });
    const requests = serveList();
    renderApp('/vulnerabilities');
    await waitFor(() => expect(bodyRows()).toHaveLength(50));
    await user.click(screen.getByRole('button', { name: 'Go to next page' }));
    await waitFor(() => expect(requests.at(-1)?.get('page')).toBe('2'));

    fireEvent.change(screen.getByRole('searchbox', { name: 'Search vulnerabilities' }), { target: { value: 'CVE-2025-110' } });
    await waitFor(() => expect(requests.at(-1)?.get('q')).toBe('CVE-2025-110'));
    await waitFor(() => expect(bodyRows()).toHaveLength(10));
    expect(requests.at(-1)?.get('page')).toBe('1');

    await user.click(screen.getByText('Fix available'));
    await waitFor(() => expect(requests.at(-1)?.get('fixable')).toBe('true'));
    await waitFor(() => expect(bodyRows()).toHaveLength(5));
  });

  it('reads the severity filter from the URL and shows the filtered empty state', async () => {
    const requests = serveList();
    renderApp('/vulnerabilities?severity=low');
    expect(await screen.findByText('No vulnerabilities match')).toBeInTheDocument();
    expect(requests.at(-1)?.get('severity')).toBe('low');
  });

  it('shows the unfiltered empty state', async () => {
    server.use(http.get('*/api/v1/vulnerabilities', () => HttpResponse.json({ items: [], total: 0 })));
    renderApp('/vulnerabilities');
    expect(await screen.findByText('No vulnerabilities')).toBeInTheDocument();
  });

  it('shows API errors', async () => {
    server.use(http.get('*/api/v1/vulnerabilities', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })));
    renderApp('/vulnerabilities');
    expect(await screen.findByText(/500: boom/)).toBeInTheDocument();
  });
});

const affected = (i: number): AffectedImage => ({
  imageId: `img-${i}`,
  ref: `ghcr.io/org/app-${i}:1.0`,
  grade: 'C',
  score: 71,
  package: 'openssl',
  installedVersion: '3.0.1',
  fixedVersion: i === 0 ? '3.0.15' : null,
  perScanner: i === 0 ? { trivy: 'critical', grype: 'high' } : { trivy: 'critical' },
  namespaces: ['apps', 'tools'],
  workloads: 2,
});

describe('Vulnerability detail page', () => {
  it('shows consensus metadata and per-scanner severities per affected image', async () => {
    const detail: VulnDetail = { ...vuln(0), description: 'Buffer overflow in openssl.', images: [affected(0), affected(1)] };
    server.use(http.get('*/api/v1/vulnerabilities/CVE-2025-1000', () => HttpResponse.json(detail)));
    renderApp('/vulnerabilities/CVE-2025-1000');
    expect(await screen.findByText('Buffer overflow in openssl.')).toBeInTheDocument();
    expect(screen.getByText('3 images · 5 workloads')).toBeInTheDocument();
    expect(screen.getByText('available')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Advisory/ })).toHaveAttribute('href', detail.url);
    const table = screen.getByRole('table', { name: 'Affected images' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByRole('link', { name: 'ghcr.io/org/app-0:1.0' })).toHaveAttribute('href', '/images/img-0');
    expect(within(rows[0]).getByText('3.0.15')).toBeInTheDocument();
    expect(within(rows[1]).getByText('no fix')).toBeInTheDocument();
    expect(within(rows[0]).getByText('apps, tools')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Go to next page' })).toBeNull(); // one page only
  });

  it('paginates long affected-image lists client-side', async () => {
    const detail: VulnDetail = { ...vuln(1), images: Array.from({ length: 60 }, (_, i) => affected(i)) };
    server.use(http.get('*/api/v1/vulnerabilities/CVE-2025-1001', () => HttpResponse.json(detail)));
    renderApp('/vulnerabilities/CVE-2025-1001');
    const table = await screen.findByRole('table', { name: 'Affected images' });
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBeLessThan(61));
    expect(screen.getByRole('button', { name: 'Go to next page' })).toBeInTheDocument();
    expect(screen.getByText('not available')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Advisory/ })).toBeNull();
  });

  it('shows the 404 from the API', async () => {
    renderApp('/vulnerabilities/CVE-1999-0000');
    expect(await screen.findByText(/vulnerability not found/)).toBeInTheDocument();
  });
});
