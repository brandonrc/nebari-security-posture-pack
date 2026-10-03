import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import type { Scan, ScanDetail } from '@/api/types';
import { server } from '@/mocks/server';
import { renderApp } from '@/test/render';

const queued = (id: number): Scan => ({
  id, trigger: 'manual', status: 'queued', startedAt: null, finishedAt: null, imagesTotal: 10, imagesDone: 0,
  imagesFailed: 0, score: null, grade: null, requestedBy: 'admin-user',
});

const detail = (id: number, over: Partial<ScanDetail> = {}): ScanDetail => ({
  ...queued(id), status: 'running', imagesDone: 3, perScanner: {}, log: ['progress'], warnings: [], ...over,
});

/** "Scan now" on the Scans page (DESIGN §7): POST /scans, then poll GET /scans/{id}. */
describe('ScanControl', () => {
  it('starts a scan, shows live progress and cancels it', async () => {
    const user = userEvent.setup();
    let status: ScanDetail['status'] = 'running';
    let posted = 0;
    server.use(
      http.post('*/api/v1/scans', () => {
        posted += 1;
        return HttpResponse.json(queued(99), { status: 202 });
      }),
      http.get('*/api/v1/scans/99', () => HttpResponse.json(detail(99, { status }))),
      http.delete('*/api/v1/scans/99', () => {
        status = 'cancelled';
        return HttpResponse.json({ ...queued(99), status: 'cancelled' });
      }),
    );
    renderApp('/scans');
    await user.click(await screen.findByRole('button', { name: /Scan now/ }));
    expect((await screen.findAllByText('Scan #99 queued'))[0]).toBeInTheDocument();
    const bar = await screen.findByRole('progressbar', { name: 'Scan #99 progress' });
    expect(bar).toHaveAttribute('aria-valuenow', '3');
    expect(screen.getByText('3/10 images')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Scan #99' })).toHaveAttribute('href', '/scans/99');
    expect(screen.getByRole('button', { name: /Scan now/ })).toBeDisabled();
    expect(posted).toBe(1);

    await user.click(screen.getByRole('button', { name: /^Cancel$/ }));
    expect((await screen.findAllByText('Scan #99 cancelled'))[0]).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole('progressbar', { name: 'Scan #99 progress' })).toBeNull());
    expect(screen.getByRole('button', { name: /Scan now/ })).toBeEnabled();
  });

  it('announces completion with the new score', async () => {
    const user = userEvent.setup();
    let polls = 0;
    server.use(
      http.post('*/api/v1/scans', () => HttpResponse.json(queued(77), { status: 202 })),
      http.get('*/api/v1/scans/77', () => {
        polls += 1;
        return HttpResponse.json(
          polls > 1 ? detail(77, { status: 'done', imagesDone: 10, imagesFailed: 1, score: 88.4, grade: 'B' }) : detail(77),
        );
      }),
    );
    renderApp('/scans');
    await user.click(await screen.findByRole('button', { name: /Scan now/ }));
    // the control polls every 3 s while the scan is in flight
    expect((await screen.findAllByText('Scan #77 complete', {}, { timeout: 8000 }))[0]).toBeInTheDocument();
    expect(screen.getAllByText(/Cluster score .* \(B\) · 10 images, 1 failed\./)[0]).toBeInTheDocument();
  });

  it('announces a failed scan with the last log line', async () => {
    const user = userEvent.setup();
    server.use(
      http.post('*/api/v1/scans', () => HttpResponse.json(queued(78), { status: 202 })),
      http.get('*/api/v1/scans/78', () => HttpResponse.json(detail(78, { status: 'failed', log: ['inventory failed: forbidden'] }))),
    );
    renderApp('/scans');
    await user.click(await screen.findByRole('button', { name: /Scan now/ }));
    expect((await screen.findAllByText('Scan #78 failed'))[0]).toBeInTheDocument();
    expect(screen.getAllByText('inventory failed: forbidden')[0]).toBeInTheDocument();
  });

  it('warns when a scan is already running (409)', async () => {
    const user = userEvent.setup();
    server.use(http.post('*/api/v1/scans', () => HttpResponse.json({ detail: 'scan 41 is already running' }, { status: 409 })));
    renderApp('/scans');
    await user.click(await screen.findByRole('button', { name: /Scan now/ }));
    expect((await screen.findAllByText('A scan is already running'))[0]).toBeInTheDocument();
    expect(screen.getAllByText('scan 41 is already running')[0]).toBeInTheDocument();
  });

  it('reports other start errors', async () => {
    const user = userEvent.setup();
    server.use(http.post('*/api/v1/scans', () => HttpResponse.json({ detail: 'worker offline' }, { status: 503 })));
    renderApp('/scans');
    await user.click(await screen.findByRole('button', { name: /Scan now/ }));
    expect((await screen.findAllByText('Could not start scan'))[0]).toBeInTheDocument();
    expect(screen.getAllByText('503: worker offline')[0]).toBeInTheDocument();
  });

  it('attaches to a scan already in flight according to /summary', async () => {
    server.use(
      http.get('*/api/v1/summary', () =>
        HttpResponse.json({ lastScan: { id: 55, status: 'running', startedAt: null, finishedAt: null, imagesTotal: 10, imagesDone: 4, imagesFailed: 0 } }),
      ),
      http.get('*/api/v1/scans/55', () => HttpResponse.json(detail(55, { imagesDone: 4 }))),
    );
    renderApp('/scans');
    expect(await screen.findByRole('progressbar', { name: 'Scan #55 progress' })).toHaveAttribute('aria-valuenow', '4');
    expect(screen.getByRole('button', { name: /Scan now/ })).toBeDisabled();
  });
});
