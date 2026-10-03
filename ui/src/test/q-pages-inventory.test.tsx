import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import type { Namespace, SeverityCounts, Workload } from '@/api/types';
import { server } from '@/mocks/server';
import { renderApp } from './render';

const counts = (c: Partial<SeverityCounts> = {}): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0, ...c });

const NAMESPACES: Namespace[] = [
  { name: 'apps', pack: 'Data Science', managed: true, score: 72, grade: 'C', workloads: 4, images: 6, counts: counts({ critical: 1, high: 3 }), posture: { passed: 30, failed: 5 } },
  { name: 'tools', pack: null, managed: false, score: 95, grade: 'A', workloads: 1, images: 1, counts: counts(), posture: { passed: 10, failed: 0 } },
];

const WORKLOADS: Workload[] = [
  {
    namespace: 'apps', kind: 'Deployment', name: 'web', pack: 'Data Science', score: 70, grade: 'C', containers: 2,
    images: [{ imageId: 'img-001', ref: 'ghcr.io/org/web:1.2.3' }, { imageId: 'img-002', ref: 'docker.io/library/nginx:1.27' }],
    posture: { passed: 12, failed: 3 }, counts: counts({ high: 2 }),
  },
  {
    namespace: 'tools', kind: 'CronJob', name: 'backup', pack: null, score: 98, grade: 'A', containers: 1,
    images: [{ imageId: 'img-003', ref: 'quay.io/org/backup:2.0' }], posture: { passed: 8, failed: 0 }, counts: counts(),
  },
];

describe('Namespaces page', () => {
  it('lists namespaces with pack, managed badge and drill-down links', async () => {
    server.use(http.get('*/api/v1/namespaces', () => HttpResponse.json(NAMESPACES)));
    renderApp('/namespaces');
    const table = await screen.findByRole('table', { name: 'Namespaces' });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(3));
    expect(within(table).getByText('managed')).toBeInTheDocument();
    expect(within(table).getByText('Data Science')).toBeInTheDocument();
    expect(within(table).getByRole('link', { name: '4' })).toHaveAttribute('href', '/workloads?namespace=apps');
    expect(within(table).getByRole('link', { name: '6 images →' })).toHaveAttribute('href', '/images?namespace=apps');

    fireEvent.change(screen.getByRole('searchbox', { name: 'Filter namespaces' }), { target: { value: 'tool' } });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(2));
    expect(within(table).getByText('tools')).toBeInTheDocument();
  });

  it('accepts an {items} envelope and shows the empty state', async () => {
    server.use(http.get('*/api/v1/namespaces', () => HttpResponse.json({ items: [] })));
    renderApp('/namespaces');
    expect(await screen.findByText('No namespaces')).toBeInTheDocument();
  });
});

describe('Workloads page', () => {
  it('lists workloads with their images and pack', async () => {
    server.use(
      http.get('*/api/v1/workloads', () => HttpResponse.json(WORKLOADS)),
      http.get('*/api/v1/namespaces', () => HttpResponse.json(NAMESPACES)),
    );
    renderApp('/workloads');
    const table = await screen.findByRole('table', { name: 'Workloads' });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(3));
    expect(within(table).getByText('apps · Deployment')).toBeInTheDocument();
    expect(within(table).getByRole('link', { name: 'web:1.2.3' })).toHaveAttribute('href', '/images/img-001');
    expect(within(table).getByRole('link', { name: 'nginx:1.27' })).toHaveAttribute('title', 'docker.io/library/nginx:1.27');
  });

  it('passes the namespace from the URL to the API and filters via the select', async () => {
    const user = userEvent.setup();
    const seen: Array<string | null> = [];
    server.use(
      http.get('*/api/v1/workloads', ({ request }) => {
        const ns = new URL(request.url).searchParams.get('namespace');
        seen.push(ns);
        return HttpResponse.json(WORKLOADS.filter((w) => !ns || w.namespace === ns));
      }),
      http.get('*/api/v1/namespaces', () => HttpResponse.json(NAMESPACES)),
    );
    renderApp('/workloads?namespace=tools');
    const table = await screen.findByRole('table', { name: 'Workloads' });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(2));
    expect(within(table).getByText('backup')).toBeInTheDocument();
    expect(seen).toContain('tools');

    await user.click(screen.getByRole('combobox', { name: 'Namespace' }));
    await user.click(await screen.findByRole('option', { name: 'All namespaces' }));
    await waitFor(() => expect(within(screen.getByRole('table', { name: 'Workloads' })).getAllByRole('row')).toHaveLength(3));
    expect(seen).toContain(null);
  });

  it('shows the empty state', async () => {
    server.use(http.get('*/api/v1/workloads', () => HttpResponse.json([])));
    renderApp('/workloads');
    expect(await screen.findByText('No workloads')).toBeInTheDocument();
  });
});

describe('Not found page', () => {
  it('renders inside the shell with a way back', async () => {
    renderApp('/definitely/not/a/page');
    expect(await screen.findByRole('heading', { name: 'Not found' })).toBeInTheDocument();
    expect(screen.getByText('This page doesn’t exist')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to overview' })).toHaveAttribute('href', '/');
    expect(screen.getByRole('navigation', { name: 'Security Posture sections' })).toBeInTheDocument();
  });
});
