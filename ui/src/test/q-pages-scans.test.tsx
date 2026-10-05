import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import type { Scan, ScanDetail } from '@/api/types';
import { server } from '@/mocks/server';
import { renderApp } from './render';

const scan = (id: number, over: Partial<Scan> = {}): Scan => ({
  id,
  trigger: 'scheduled',
  status: 'done',
  startedAt: '2026-10-01T10:00:00Z',
  finishedAt: '2026-10-01T10:12:30Z',
  imagesTotal: 40,
  imagesDone: 40,
  imagesFailed: 0,
  score: 81.5,
  grade: 'B',
  requestedBy: null,
  ...over,
});

describe('Scans page', () => {
  it('lists the scan history with status, trigger, duration, images and score', async () => {
    server.use(
      http.get('*/api/v1/scans', () =>
        HttpResponse.json([
          scan(12, { trigger: 'manual', requestedBy: 'admin-user', imagesFailed: 3, imagesDone: 37 }),
          scan(11, { status: 'failed', score: null, grade: null, finishedAt: null }),
        ]),
      ),
    );
    renderApp('/scans');
    const table = await screen.findByRole('table', { name: 'Scan history' });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(3));
    const [, first, second] = within(table).getAllByRole('row');
    expect(within(first).getByRole('link', { name: '#12' })).toHaveAttribute('href', '/scans/12');
    expect(within(first).getByText('admin-user')).toBeInTheDocument();
    expect(within(first).getByText('(3 failed)')).toBeInTheDocument();
    expect(within(first).getByText('12m 30s')).toBeInTheDocument();
    expect(within(second).getByText('—')).toBeInTheDocument(); // no grade for the failed scan
    expect(screen.getByRole('button', { name: /Scan now/ })).toBeEnabled();
  });

  it('explains image counts: rescanned, fresh, in inventory; event scans show their targets', async () => {
    server.use(
      http.get('*/api/v1/scans', () =>
        HttpResponse.json([
          scan(31, { trigger: 'event', requestedBy: 'pod-watcher', imagesTotal: 1, imagesDone: 1, imagesInventoried: 80, imagesRescanned: 1, imagesSkippedFresh: 2, imagesTargeted: 3 }),
          scan(30, { imagesTotal: 68, imagesDone: 68, imagesInventoried: 80, imagesRescanned: 68, imagesSkippedFresh: 12, imagesTargeted: null }),
          scan(29, { imagesTotal: 0, imagesDone: 0, imagesInventoried: 80, imagesRescanned: 0, imagesSkippedFresh: 80, imagesTargeted: null }),
        ]),
      ),
    );
    renderApp('/scans');
    const table = await screen.findByRole('table', { name: 'Scan history' });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(4));
    const [, event, full, fresh] = within(table).getAllByRole('row');
    expect(within(event).getByText('3 targeted · 1 rescanned · 2 fresh')).toBeInTheDocument();
    expect(within(full).getByText('68 rescanned · 12 fresh · 80 in inventory')).toBeInTheDocument();
    expect(within(fresh).getByText('0 rescanned · 80 fresh · 80 in inventory')).toBeInTheDocument();
  });

  it('shows the empty state', async () => {
    server.use(http.get('*/api/v1/scans', () => HttpResponse.json({ items: [] })));
    renderApp('/scans');
    expect(await screen.findByText('No scans yet')).toBeInTheDocument();
  });
});

function detail(over: Partial<ScanDetail> = {}): ScanDetail {
  return {
    ...scan(5),
    perScanner: { trivy: { ok: 38, error: 2 }, grype: { ok: 40, error: 0 } },
    log: ['inventory: 40 images', 'ERROR clair: timeout on img-7', 'scan done'],
    warnings: ['clair: 2 images unsupported'],
    ...over,
  };
}

describe('Scan detail page', () => {
  it('shows status, per-scanner counts, warnings and the log tail', async () => {
    server.use(http.get('*/api/v1/scans/5', () => HttpResponse.json(detail())));
    renderApp('/scans/5');
    expect(await screen.findByText('inventory: 40 images')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Scan #5' })).toBeInTheDocument();
    expect(screen.getByText('clair: 2 images unsupported')).toBeInTheDocument();
    expect(screen.getAllByText('40 images attempted')).toHaveLength(2); // trivy 38 + 2, grype 40
    expect(screen.getByText('no runs recorded')).toBeInTheDocument(); // clair
    expect(screen.getByText('ERROR clair: timeout on img-7').className).toMatch(/destructive/);
    expect(screen.queryByRole('button', { name: /Cancel scan/ })).toBeNull();
    expect(screen.queryByRole('progressbar')).toBeNull();
  });

  it('splits a string log tail into lines', async () => {
    server.use(http.get('*/api/v1/scans/6', () => HttpResponse.json({ ...detail({ id: 6 }), log: undefined, logTail: 'first line\nsecond line' })));
    renderApp('/scans/6');
    expect(await screen.findByText('second line')).toBeInTheDocument();
    expect(screen.getByText('first line')).toBeInTheDocument();
  });

  it('shows "No log lines." for an empty log', async () => {
    server.use(http.get('*/api/v1/scans/7', () => HttpResponse.json(detail({ id: 7, log: [], warnings: [] }))));
    renderApp('/scans/7');
    expect(await screen.findByText('No log lines.')).toBeInTheDocument();
  });

  it('cancels a running scan', async () => {
    const user = userEvent.setup();
    let cancelled = false;
    server.use(
      http.get('*/api/v1/scans/8', () =>
        HttpResponse.json(detail({ id: 8, status: cancelled ? 'cancelled' : 'running', imagesDone: 10, finishedAt: null, warnings: [] })),
      ),
      http.delete('*/api/v1/scans/8', () => {
        cancelled = true;
        return HttpResponse.json(scan(8, { status: 'cancelled' }));
      }),
    );
    renderApp('/scans/8');
    const progress = await screen.findByRole('progressbar', { name: 'Scan progress' });
    expect(progress).toHaveAttribute('aria-valuenow', '10');
    await user.click(screen.getByRole('button', { name: /Cancel scan/ }));
    expect((await screen.findAllByText('Cancelling scan #8'))[0]).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole('button', { name: /Cancel scan/ })).toBeNull());
    expect(cancelled).toBe(true);
  });

  it('toasts a failed cancel', async () => {
    const user = userEvent.setup();
    server.use(
      http.get('*/api/v1/scans/9', () => HttpResponse.json(detail({ id: 9, status: 'queued', finishedAt: null }))),
      http.delete('*/api/v1/scans/9', () => HttpResponse.json({ detail: 'already finished' }, { status: 409 })),
    );
    renderApp('/scans/9');
    await user.click(await screen.findByRole('button', { name: /Cancel scan/ }));
    expect((await screen.findAllByText('Cancel failed'))[0]).toBeInTheDocument();
    expect(screen.getAllByText('409: already finished')[0]).toBeInTheDocument();
  });

  it('shows the 404 from the API', async () => {
    renderApp('/scans/424242');
    expect(await screen.findByText(/scan not found/)).toBeInTheDocument();
  });
});
