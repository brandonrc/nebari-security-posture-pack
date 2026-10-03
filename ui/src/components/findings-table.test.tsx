import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { delay, http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import type { Finding, ImageDetail, ScannerName, Severity } from '@/api/types';
import { images } from '@/mocks/fixtures';
import { imageWithFindingsPage } from '@/mocks/handlers';
import { server } from '@/mocks/server';
import { renderApp } from '@/test/render';

const SEVS: Severity[] = ['critical', 'high', 'medium', 'low'];
const ALL: ScannerName[] = ['trivy', 'grype', 'clair'];
const ok = { status: 'ok' as const, findings: 0, durationMs: 1 };

// 260 findings: every 4th is critical; every other one is flagged by all three scanners
const findings: Finding[] = Array.from({ length: 260 }, (_, i) => {
  const scanners = i % 2 === 0 ? ALL : (['trivy'] as ScannerName[]);
  const severity = SEVS[i % 4];
  return {
    vulnId: `CVE-2024-${String(10000 + i)}`,
    severity,
    package: `pkg-${i}`,
    installedVersion: '1.0.0',
    fixedVersion: i % 3 === 0 ? '1.0.1' : null,
    pkgType: 'deb',
    scanners,
    agreement: scanners.length / 3,
    perScanner: Object.fromEntries(scanners.map((s) => [s, severity])),
    cvss: null,
    title: null,
    url: null,
    fixable: i % 3 === 0,
  };
});
const image: ImageDetail = { ...images[0], id: 'img-big', findings, scanners: { trivy: ok, grype: ok, clair: ok }, warnings: [] };

/** Serve `img-big` through the real mock paging and record each request's query. */
function serve(transform: (body: ImageDetail, params: URLSearchParams) => ImageDetail = (b) => b, wait = 0) {
  const requests: URLSearchParams[] = [];
  server.use(
    http.get('*/api/v1/images/img-big', async ({ request }) => {
      const params = new URL(request.url).searchParams;
      requests.push(params);
      if (wait && params.get('page') !== '1') await delay(wait);
      return HttpResponse.json(transform(imageWithFindingsPage(image, params), params));
    }),
  );
  return requests;
}
const last = (requests: URLSearchParams[]) => Object.fromEntries(requests[requests.length - 1]);
const table = () => screen.getByRole('table', { name: 'Findings' });
const bodyRows = () => within(table()).getAllByRole('row').slice(1);

describe('FindingsTable server-side paging', () => {
  it('requests the first page and takes totals and the agreement line from the server', async () => {
    // the server's flaggedByAll wins over anything computable from the 50 rows on the page
    const requests = serve((b) => ({ ...b, findingsSummary: { ...b.findingsSummary!, flaggedByAll: 7 } }));
    renderApp('/images/img-big');
    expect(await screen.findByText('7 of 260 flagged by all 3 scanners')).toBeInTheDocument();
    expect(last(requests)).toEqual({ page: '1', pageSize: '50', sort: 'severity', order: 'desc' });
    expect(bodyRows()).toHaveLength(50);
    expect(screen.getByText('1–50 of 260')).toBeInTheDocument();
    expect(screen.getByText('Page 1 of 6')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Findings/ })).toHaveTextContent('260');
  });

  it('fetches each page from the server (critical first) with a skeleton while loading', async () => {
    const user = userEvent.setup();
    const requests = serve(undefined, 150);
    renderApp('/images/img-big');
    await screen.findByText('1–50 of 260');
    expect(bodyRows().every((r) => within(r).getAllByText('Critical').length > 0)).toBe(true);
    await user.click(screen.getByRole('button', { name: 'Go to next page' }));
    await waitFor(() => expect(table()).toHaveAttribute('aria-busy', 'true'));
    await waitFor(() => expect(table()).not.toHaveAttribute('aria-busy'));
    expect(last(requests)).toMatchObject({ page: '2', pageSize: '50' });
    expect(screen.getByText('51–100 of 260')).toBeInTheDocument();
    // 65 criticals: 15 spill onto page 2
    expect(within(bodyRows()[14]).getAllByText('Critical').length).toBeGreaterThan(0);
    expect(within(bodyRows()[15]).queryAllByText('Critical')).toHaveLength(0);
    await user.click(screen.getByRole('button', { name: 'Go to last page' }));
    await waitFor(() => expect(last(requests)).toMatchObject({ page: '6' }));
    await waitFor(() => expect(bodyRows()).toHaveLength(10));
  });

  it('sends a debounced search and filters as query params and returns to page 1', async () => {
    // delay: null types without yielding between keystrokes, so a slow (coverage-instrumented) run
    // cannot space them past the debounce window and fire one request per key.
    const user = userEvent.setup({ delay: null });
    const requests = serve();
    renderApp('/images/img-big');
    await screen.findByText('1–50 of 260');
    await user.click(screen.getByRole('button', { name: 'Go to next page' }));
    await screen.findByText('51–100 of 260');
    await user.type(screen.getByRole('searchbox', { name: 'Search findings' }), 'CVE-2024-101');
    // CVE-2024-10100 … 10199 → 100 matches, half agreed by all three
    expect(await screen.findByText('50 of 100 flagged by all 3 scanners')).toBeInTheDocument();
    const searches = requests.filter((p) => p.has('q'));
    expect(searches.map((p) => p.get('q'))).toEqual(['CVE-2024-101']); // one request, not one per keystroke
    expect(last(requests)).toMatchObject({ q: 'CVE-2024-101', page: '1' });
    expect(screen.getByText('1–50 of 100')).toBeInTheDocument();

    await user.click(screen.getByText('Disagreements only'));
    expect(await screen.findByText('0 of 50 flagged by all 3 scanners')).toBeInTheDocument();
    expect(last(requests)).toMatchObject({ q: 'CVE-2024-101', disagree: 'true', page: '1' });
    expect(screen.getByRole('button', { name: 'Go to next page' })).toBeDisabled();
  });

  it('binds the fixable toggle and column sort to query params', async () => {
    const user = userEvent.setup();
    const requests = serve();
    renderApp('/images/img-big');
    await screen.findByText('1–50 of 260');
    await user.click(screen.getByText('Fixable only'));
    // every 3rd finding is fixable → 87, half of those (even indices) agreed by all
    expect(await screen.findByText('44 of 87 flagged by all 3 scanners')).toBeInTheDocument();
    expect(last(requests)).toMatchObject({ fixable: 'true', page: '1' });
    await user.click(within(screen.getByRole('columnheader', { name: /Package/ })).getByRole('button'));
    await waitFor(() => expect(last(requests)).toMatchObject({ sort: 'package', order: 'asc', fixable: 'true', page: '1' }));
    await waitFor(() => expect(within(bodyRows()[0]).getByText('pkg-0')).toBeInTheDocument());
  });

  it('changes the page size on the server (25/50/100/250)', async () => {
    const user = userEvent.setup();
    const requests = serve();
    renderApp('/images/img-big');
    await screen.findByText('1–50 of 260');
    await user.click(screen.getByRole('combobox', { name: 'Rows per page' }));
    expect((await screen.findAllByRole('option')).map((o) => o.textContent)).toEqual(['25', '50', '100', '250']);
    await user.click(screen.getByRole('option', { name: '250' }));
    await screen.findByText('1–250 of 260');
    expect(last(requests)).toMatchObject({ pageSize: '250', page: '1' });
    expect(screen.getByText('Page 1 of 2')).toBeInTheDocument();
  });

  it('warns when the server truncated the list', async () => {
    serve((b) => ({ ...b, truncated: true }));
    renderApp('/images/img-big');
    expect(await screen.findByText('Findings list truncated')).toBeInTheDocument();
  });
});
