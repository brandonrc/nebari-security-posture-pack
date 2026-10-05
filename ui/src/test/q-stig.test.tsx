import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import type { Settings } from '@/api/types';
import { images } from '@/mocks/fixtures';
import { stigBenchmarkCatalogue } from '@/mocks/scap';
import { server } from '@/mocks/server';
import { renderApp } from './render';

/** §14 SCAP views against the MSW fixtures (src/mocks/scap.ts). */
const idOf = (ref: string) => images.find((i) => i.ref.startsWith(ref))?.id as string;
const API_IMAGE = idOf('localhost:32000/security-posture-api'); // Ubuntu 22.04 SSG + PostgreSQL 15
const CALICO = idOf('docker.io/calico/node'); // RHEL 9, degraded rootfs
const PYTHON = idOf('docker.io/library/python'); // no applicable benchmark

describe('Image detail → STIG tab', () => {
  it('shows one sub-tab per benchmark with header, rule table and fix-text expander', async () => {
    const user = userEvent.setup();
    renderApp(`/images/${API_IMAGE}?tab=stig`);
    const tabs = await screen.findByRole('tablist', { name: 'Benchmarks' }, { timeout: 5000 });
    expect(within(tabs).getAllByRole('tab')).toHaveLength(2);
    expect(await screen.findByRole('heading', { name: 'Canonical Ubuntu 22.04 LTS STIG (ComplianceAsCode)' })).toBeInTheDocument();
    expect(screen.getByText('SSG')).toBeInTheDocument();
    expect(screen.getByText('xccdf_org.ssgproject.content_profile_stig')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /\d+ pass, \d+ fail, \d+ error, \d+ not applicable, \d+ not checked/ })).toBeInTheDocument();
    expect(screen.getByLabelText(/CAT I open: \d+/)).toBeInTheDocument();
    expect(screen.getAllByRole('img', { name: /Score .* of 100, grade/ }).length).toBeGreaterThan(0);

    const table = screen.getByRole('table', { name: 'STIG rules' });
    expect(within(table).getAllByRole('row').length).toBe(31); // header + 30 rules
    expect(within(table).getAllByText(/^CCI-\d+$/).length).toBeGreaterThan(0);
    const expand = within(table).getAllByRole('button', { name: /Show fix text for/ })[0];
    await user.click(expand);
    expect(expand).toHaveAttribute('aria-expanded', 'true');
    expect(within(table).getByText('Fix text')).toBeInTheDocument();

    // second benchmark
    await user.click(within(tabs).getByRole('tab', { name: /PostgreSQL 15 STIG/ }));
    expect(await screen.findByRole('heading', { name: 'PostgreSQL 15 STIG' })).toBeInTheDocument();
    expect(screen.getByText('DISA')).toBeInTheDocument();
    expect(await screen.findByText(/^PostgreSQL must not use trust authentication/)).toBeInTheDocument();
  });

  it('filters rules server-side by result and category and pages them', async () => {
    const user = userEvent.setup();
    const seen: URLSearchParams[] = [];
    server.events.on('request:start', ({ request }) => {
      const url = new URL(request.url);
      if (url.pathname.endsWith('/stig')) seen.push(url.searchParams);
    });
    renderApp(`/images/${API_IMAGE}?tab=stig`);
    const table = await screen.findByRole('table', { name: 'STIG rules' });
    await user.click(screen.getByRole('combobox', { name: 'Result' }));
    await user.click(await screen.findByRole('option', { name: 'Fail' }));
    await waitFor(() => expect(seen.at(-1)?.get('result')).toBe('fail'));
    await waitFor(() => {
      const rows = within(table).getAllByRole('row').slice(1);
      expect(rows.length).toBeGreaterThan(0);
      for (const r of rows) expect(within(r).getByText('Fail')).toBeInTheDocument();
    });
    await user.click(screen.getByRole('combobox', { name: 'Category' }));
    await user.click(await screen.findByRole('option', { name: 'CAT II' }));
    await waitFor(() => expect(seen.at(-1)?.get('severity')).toBe('cat2'));
    fireEvent.change(screen.getByRole('searchbox', { name: 'Search rules' }), { target: { value: 'zzz-no-such-rule' } });
    // Fail + CAT II alone can already be empty ("No rules match"), and the debounced q refetch then
    // swaps it for skeleton rows: wait for the q request and its result, not the first match.
    await waitFor(() => expect(seen.at(-1)?.get('q')).toBe('zzz-no-such-rule'));
    await waitFor(() => expect(within(table).getByText('No rules match')).toBeInTheDocument());
    expect(table).not.toHaveAttribute('aria-busy');
    await user.click(screen.getByRole('button', { name: 'Clear filters' }));
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBe(31));
    await user.click(screen.getByRole('combobox', { name: 'Rows per page' }));
    await user.click(await screen.findByRole('option', { name: '25' }));
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBe(26));
    await user.click(screen.getByRole('button', { name: 'Go to next page' }));
    await waitFor(() => expect(seen.at(-1)?.get('page')).toBe('2'));
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBe(6));
    server.events.removeAllListeners();
  });

  it('warns when rootfs fidelity is degraded', async () => {
    renderApp(`/images/${CALICO}?tab=stig`);
    expect(await screen.findByText('Rootfs extraction was degraded')).toBeInTheDocument();
    expect(screen.getByText('214 extended attributes could not be restored')).toBeInTheDocument();
    expect(screen.getByText(/file capabilities could not be restored/)).toBeInTheDocument();
    expect(screen.queryByRole('tablist', { name: 'Benchmarks' })).toBeNull();
    expect(screen.getByRole('heading', { name: 'Red Hat Enterprise Linux 9 STIG' })).toBeInTheDocument();
  });

  it('shows the "no applicable benchmark" state', async () => {
    renderApp(`/images/${PYTHON}?tab=stig`);
    expect(await screen.findByText('No applicable benchmark')).toBeInTheDocument();
    expect(screen.getByText(/os-release and product probes found no applicable benchmark/)).toBeInTheDocument();
    // the tab carries "n/a" instead of a score
    expect(screen.getByRole('tab', { name: /STIG/ })).toHaveTextContent('n/a');
  });

  it('degrades to an empty state when the API has no /stig endpoint', async () => {
    server.use(http.get('*/api/v1/images/:id/stig', () => HttpResponse.json({ detail: 'Not Found' }, { status: 404 })));
    renderApp(`/images/${API_IMAGE}?tab=stig`);
    expect(await screen.findByText('No SCAP results')).toBeInTheDocument();
  });

  it('computes CAT chips from the rules when the summary lacks them and shows API errors', async () => {
    server.use(
      http.get('*/api/v1/images/:id/stig', () =>
        HttpResponse.json({
          benchmarks: [
            {
              benchmarkId: 'b',
              title: 'Bench',
              version: '1',
              source: 'ssg',
              profileId: 'p',
              summary: { pass: 1, fail: 2, score: 50 },
              rules: [
                { ruleId: 'r1', stigId: 'V-1', cci: 'CCI-1, CCI-2', severity: 'high', result: 'fail', title: 'One' },
                { ruleId: 'r2', severity: 'CAT III', result: 'FAIL', title: 'Two' },
                { ruleId: 'r3', severity: 'medium', result: 'pass', title: 'Three' },
              ],
            },
          ],
        }),
      ),
    );
    renderApp(`/images/${API_IMAGE}?tab=stig`);
    expect(await screen.findByLabelText('CAT I open: 1')).toBeInTheDocument();
    expect(screen.getByLabelText('CAT II open: 0')).toBeInTheDocument();
    expect(screen.getByLabelText('CAT III open: 1')).toBeInTheDocument();
    expect(screen.getByText('CCI-2')).toBeInTheDocument();
  });

  it.each([
    ['error', 'SCAP evaluation failed'],
    ['timeout', 'SCAP evaluation timed out'],
    ['notEvaluated', 'Not evaluated yet'],
    ['noContent', 'No SCAP content for this image'],
  ])('image-level status %s has its own empty state', async (status, title) => {
    server.use(http.get('*/api/v1/images/:id/stig', () => HttpResponse.json({ status, benchmarks: [], reason: 'why: because' })));
    renderApp(`/images/${API_IMAGE}?tab=stig`);
    expect(await screen.findByText(title)).toBeInTheDocument();
    if (status !== 'notEvaluated') expect(screen.getByText(/why: because/)).toBeInTheDocument();
  });

  it('shows a retryable error for other failures', async () => {
    server.use(http.get('*/api/v1/images/:id/stig', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })));
    renderApp(`/images/${API_IMAGE}?tab=stig`);
    expect(await screen.findByText('500: boom')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument();
  });
});

describe('Compliance → STIG → Product STIGs', () => {
  it('lists one row per benchmark next to the Kubernetes STIG and links to the benchmark page', async () => {
    renderApp('/compliance?tab=stig');
    expect(await screen.findByText('Kubernetes STIG')).toBeInTheDocument();
    const table = await screen.findByRole('table', { name: 'Product STIG benchmarks' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(3);
    const pg = stigBenchmarkCatalogue().find((b) => b.id === 'disa-postgresql15');
    const row = rows.find((r) => within(r).queryByText('PostgreSQL 15 STIG')) as HTMLElement;
    expect(within(row).getByRole('link', { name: 'PostgreSQL 15 STIG' })).toHaveAttribute('href', '/stig/benchmarks/disa-postgresql15');
    expect(within(row).getByText(String(pg?.imagesEvaluated))).toBeInTheDocument();
    expect(within(row).getByText('V1R2')).toBeInTheDocument();
    expect(within(row).getByText(/^\d+%$/)).toBeInTheDocument();
    expect(within(row).getByLabelText(`CAT I open: ${pg?.cat1Open}`)).toBeInTheDocument();
  });

  it('falls back to GET /stig/benchmarks when /compliance/stig is the pre-§14 bare list', async () => {
    server.use(http.get('*/api/v1/compliance/stig', () => HttpResponse.json([])));
    renderApp('/compliance?tab=stig');
    const table = await screen.findByRole('table', { name: 'Product STIG benchmarks' });
    expect(within(table).getAllByRole('row')).toHaveLength(4);
  });

  it('shows the empty state when nothing was evaluated', async () => {
    server.use(http.get('*/api/v1/compliance/stig', () => HttpResponse.json({ items: [], product: [] })));
    renderApp('/compliance?tab=stig#product-stigs');
    expect(await screen.findByText('No product STIG results')).toBeInTheDocument();
  });

  it('shows an error when neither source answers', async () => {
    server.use(
      http.get('*/api/v1/compliance/stig', () => HttpResponse.json({ items: [] })),
      http.get('*/api/v1/stig/benchmarks', () => HttpResponse.json({ detail: 'nope' }, { status: 500 })),
    );
    renderApp('/compliance?tab=stig');
    expect(await screen.findByText('Couldn’t load product STIG benchmarks')).toBeInTheDocument();
  });
});

describe('Benchmark page', () => {
  it('lists failing rules across images and expands to the image list', async () => {
    const user = userEvent.setup();
    renderApp('/stig/benchmarks/disa-postgresql15');
    expect(await screen.findByRole('heading', { level: 1, name: 'PostgreSQL 15 STIG' })).toBeInTheDocument();
    const table = await screen.findByRole('table', { name: 'Benchmark rules' });
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBeGreaterThan(1));
    const failingRows = within(table).getAllByRole('row').slice(1);
    const allRows = 30;
    expect(failingRows.length).toBeLessThan(allRows);
    expect(screen.getByRole('link', { name: 'Product STIGs' })).toHaveAttribute('href', '/compliance?tab=stig#product-stigs');

    const first = failingRows[0];
    await user.click(within(first).getByRole('button', { name: /Show images for/ }));
    const list = await screen.findByRole('list', { name: /Images evaluated for/ });
    const links = within(list).getAllByRole('link');
    expect(String(links.length)).toBe(within(first).getAllByRole('cell')[4].textContent);
    expect(links[0].getAttribute('href')).toMatch(/^\/images\/img-\d+\?tab=stig$/);
    expect(within(list).getAllByText('Fail')).toHaveLength(links.length);

    await user.click(screen.getByText('Failing only'));
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBe(allRows + 1 + 1)); // + header + the expanded row
    fireEvent.change(screen.getByRole('searchbox', { name: 'Search benchmark rules' }), { target: { value: 'pg_hba' } });
    await waitFor(() => expect(within(table).getAllByRole('button', { name: /images for/ })).toHaveLength(1));
    expect(within(table).getByText(/must not use trust authentication/)).toBeInTheDocument();
    await user.click(screen.getByRole('combobox', { name: 'Category' }));
    await user.click(await screen.findByRole('option', { name: 'CAT III' }));
    expect(await screen.findByText('No rules match')).toBeInTheDocument();
  });

  it('reads the benchmark row from the rules response when the catalogue lacks it', async () => {
    server.use(http.get('*/api/v1/stig/benchmarks', () => HttpResponse.json([{ id: null, title: 'content only', imagesEvaluated: 0 }])));
    renderApp('/stig/benchmarks/disa-rhel9');
    expect(await screen.findByRole('heading', { level: 1, name: 'Red Hat Enterprise Linux 9 STIG' })).toBeInTheDocument();
    expect(screen.getByText('V2R5')).toBeInTheDocument();
  });

  it('accepts image arrays in failingImages/passingImages and an unknown benchmark', async () => {
    server.use(
      http.get('*/api/v1/stig/benchmarks', () => HttpResponse.json([])),
      http.get('*/api/v1/stig/benchmarks/:id/rules', () =>
        HttpResponse.json([{ ruleId: 'r1', stigId: 'V-9', cat: 'I', title: 'Rule one', failingImages: [{ imageId: 'img-001', ref: 'a:1' }, 'img-002'], passingImages: [] }]),
      ),
    );
    const user = userEvent.setup();
    renderApp('/stig/benchmarks/custom');
    const table = await screen.findByRole('table', { name: 'Benchmark rules' });
    const row = (await within(table).findByText('Rule one')).closest('tr') as HTMLElement;
    expect(within(row).getByText('2')).toBeInTheDocument();
    expect(within(row).getByText('CAT I')).toBeInTheDocument();
    await user.click(within(row).getByRole('button', { name: 'Show images for V-9' }));
    expect(await screen.findByRole('link', { name: 'a:1' })).toHaveAttribute('href', '/images/img-001?tab=stig');
    expect(screen.getByLabelText('CAT I open: 2')).toBeInTheDocument();
  });
});

describe('Overview STIG tile and SCAP scanner card', () => {
  it('shows evaluated images, coverage and open CAT I linking to Product STIGs', async () => {
    renderApp('/');
    const tile = await screen.findByTestId('stig-tile');
    expect(within(tile).getByRole('link', { name: /\d+ images evaluated against a STIG benchmark/ })).toHaveAttribute('href', '/compliance?tab=stig#product-stigs');
    expect(within(tile).getByText(/images evaluated · \d+% coverage/)).toBeInTheDocument();
    expect(Number(within(tile).getByTestId('stig-cat1').textContent)).toBeGreaterThan(0);
    // like the API, the summary lists only the vulnerability scanners: `scap` comes from /scanners
    const card = await screen.findByTestId('scanner-scap');
    expect(within(card).getByText('OpenSCAP')).toBeInTheDocument();
    expect(within(card).getByText(/SCAP content fetched/)).toBeInTheDocument();
    expect(await within(card).findByText('Red Hat Enterprise Linux 9 STIG')).toBeInTheDocument();
    expect(within(card).getByText('0.1.76')).toBeInTheDocument();
  });

  it('hides the tile without summary.stig and takes the scap card from /scanners', async () => {
    server.use(
      http.get('*/api/v1/summary', () => HttpResponse.json({ score: 80, grade: 'B', scanners: [{ name: 'trivy', version: '1', dbUpdatedAt: null, healthy: true, lastError: null }] })),
      http.get('*/api/v1/scanners', () =>
        HttpResponse.json([{ name: 'scap', enabled: true, version: '1.3.10', dbUpdatedAt: null, healthy: false, lastError: 'content fetch failed', lastRunAt: null, contentVersions: [] }]),
      ),
    );
    renderApp('/');
    const card = await screen.findByTestId('scanner-scap');
    expect(within(card).getByText('content fetch failed')).toBeInTheDocument();
    expect(screen.queryByTestId('stig-tile')).toBeNull();
  });
});

describe('Images STIG column', () => {
  it('shows the score or n/a, sorts and filters server-side', async () => {
    const user = userEvent.setup();
    const seen: URLSearchParams[] = [];
    server.events.on('request:start', ({ request }) => {
      const url = new URL(request.url);
      if (url.pathname.endsWith('/images')) seen.push(url.searchParams);
    });
    renderApp('/images');
    const table = await screen.findByRole('table', { name: 'Images' });
    await waitFor(() => expect(within(table).getAllByTestId('stig-cell').length).toBeGreaterThan(20));
    const cells = within(table).getAllByTestId('stig-cell');
    expect(cells.filter((c) => c.textContent === 'n/a').length).toBe(19);
    expect(within(table).getAllByRole('link', { name: /Grade [A-F]/ }).every((l) => l.getAttribute('href')?.endsWith('?tab=stig'))).toBe(true);

    await user.click(within(within(table).getByRole('columnheader', { name: /STIG/ })).getByRole('button'));
    await waitFor(() => expect(seen.at(-1)?.get('sort')).toBe('stig'));
    await user.click(screen.getByRole('combobox', { name: 'STIG' }));
    await user.click(await screen.findByRole('option', { name: 'Open CAT I' }));
    await waitFor(() => expect(seen.at(-1)?.get('stig')).toBe('cat1'));
    await waitFor(() => expect(within(table).getAllByTestId('stig-cell').every((c) => c.textContent !== 'n/a')).toBe(true));
    server.events.removeAllListeners();
  });

  it('marks SCAP errors and links numeric API image ids', async () => {
    server.use(
      http.get('*/api/v1/images', () =>
        HttpResponse.json({
          items: [
            { id: 7, ref: 'x/y:1', stig: { status: 'timeout', score: null, error: 'budget' } },
            { id: 8, ref: 'x/z:1', stig: { status: 'evaluated', score: 72.5 } },
          ],
          total: 2,
        }),
      ),
    );
    renderApp('/images');
    const table = await screen.findByRole('table', { name: 'Images' });
    expect(await within(table).findByRole('link', { name: 'timeout' })).toHaveAttribute('href', '/images/7?tab=stig');
    expect(within(table).getByRole('link', { name: 'x/z:1' })).toHaveAttribute('href', '/images/8');
    expect(within(table).getByText('72.5')).toBeInTheDocument();
  });

  it('hides the column when the API serves no stig field', async () => {
    server.use(http.get('*/api/v1/images', () => HttpResponse.json({ items: [{ id: 'x', ref: 'a/b:1', registry: 'a', repository: 'b' }], total: 1 })));
    renderApp('/images');
    const table = await screen.findByRole('table', { name: 'Images' });
    await within(table).findByText('a/b:1');
    expect(within(table).queryByRole('columnheader', { name: /STIG/ })).toBeNull();
    expect(screen.queryByRole('combobox', { name: 'STIG' })).toBeNull();
  });
});

describe('Settings → SCAP', () => {
  it('edits the toggle, preference and timeout; lists content sources read-only with versions', async () => {
    const user = userEvent.setup();
    let saved: Settings | null = null;
    server.use(
      http.put('*/api/v1/settings', async ({ request }) => {
        saved = (await request.json()) as Settings;
        return HttpResponse.json(saved);
      }),
    );
    renderApp('/settings');
    expect(await screen.findByText('SCAP (product and OS STIGs)')).toBeInTheDocument();
    const sources = screen.getByRole('table', { name: 'SCAP content sources' });
    expect(within(sources).getAllByRole('row')).toHaveLength(4);
    expect(within(sources).getByText('disa-rhel9')).toBeInTheDocument();
    expect(await within(sources).findByText('V2R5')).toBeInTheDocument();
    expect(within(sources).getByText('0.1.76')).toBeInTheDocument();
    expect(within(sources).getAllByText('DISA')).toHaveLength(2);

    await user.click(screen.getByText('Prefer DISA benchmarks'));
    const timeout = screen.getByLabelText('Timeout per image');
    fireEvent.change(timeout, { target: { value: '10' } });
    expect(screen.getByRole('button', { name: /Save settings/ })).toBeDisabled();
    fireEvent.change(timeout, { target: { value: '1200' } });
    await user.click(screen.getByText('Run SCAP evaluation during scans'));
    await user.click(screen.getByRole('button', { name: /Save settings/ }));
    await waitFor(() => expect(saved).not.toBeNull());
    const body = saved as unknown as Settings;
    expect(body.scanners.scap).toBe(false);
    expect(body.scap).toMatchObject({ preferDisa: false, timeoutSeconds: 1200 });
    expect(body.scap?.sources).toHaveLength(3);
  });

  it('is hidden for an API without SCAP settings and versions come from /scanners', async () => {
    const base = { scanIntervalHours: 6, rescanAfterHours: 24, excludedNamespaces: [], parallelism: 2, adminGroups: ['admin'] };
    server.use(http.get('*/api/v1/settings', () => HttpResponse.json({ ...base, scanners: { trivy: true, grype: true, clair: true } })));
    const { unmount } = renderApp('/settings');
    expect(await screen.findByText('Control evidence engine')).toBeInTheDocument();
    expect(screen.queryByText('SCAP (product and OS STIGs)')).toBeNull();
    unmount();

    server.use(
      http.get('*/api/v1/settings', () =>
        HttpResponse.json({ ...base, scanners: { trivy: true, grype: true, clair: true, scap: true }, scap: { sources: [{ url: 'https://dl.dod.cyber.mil/x/U_RHEL_9_V2R5_STIG_SCAP_1-3_Benchmark.zip' }] } }),
      ),
    );
    renderApp('/settings');
    const sources = await screen.findByRole('table', { name: 'SCAP content sources' });
    expect(await within(sources).findByText('V2R5')).toBeInTheDocument();
    expect(within(sources).getByText('DISA')).toBeInTheDocument();
    expect(screen.getByLabelText('Timeout per image')).toHaveValue(900);
  });
});
