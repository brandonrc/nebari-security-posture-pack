import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import type { Check, CheckDetail } from '@/api/types';
import { server } from '@/mocks/server';
import { renderApp } from './render';

const CHECKS: Check[] = [
  {
    id: 'privileged',
    title: 'Privileged container',
    severity: 'critical',
    category: 'privilege',
    description: 'Container runs privileged.',
    remediation: 'Remove `privileged: true`.',
    passed: 40,
    failed: 2,
    controls: ['AC-6', 'CM-7'],
    stig: { vulnId: 'V-242414', ruleId: 'SV-242414r1_rule', cat: 'I' },
  },
  {
    id: 'no-liveness-probe',
    title: 'No liveness probe',
    severity: 'low',
    category: 'reliability',
    description: 'No liveness probe.',
    remediation: 'Add a livenessProbe.',
    passed: 30,
    failed: 12,
    controls: [],
    stig: null,
  },
];

const DETAIL: CheckDetail = {
  ...CHECKS[0],
  results: [
    { namespace: 'kube-system', kind: 'DaemonSet', name: 'calico-node', container: 'calico-node', status: 'fail', detail: 'privileged: true', systemNamespace: true },
    { namespace: 'apps', kind: 'Deployment', name: 'web', container: 'web', status: 'fail', detail: 'privileged: true' },
    { namespace: 'apps', kind: 'Deployment', name: 'api', container: 'api', status: 'pass', detail: 'not privileged' },
  ],
};

describe('Posture checks page', () => {
  it('lists the catalogue with severity, pass/fail, controls and STIG, and filters by text', async () => {
    server.use(http.get('*/api/v1/checks', () => HttpResponse.json(CHECKS)));
    renderApp('/checks');
    const table = await screen.findByRole('table', { name: 'Posture checks' });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(3));
    expect(screen.getByRole('heading', { name: 'Posture checks' })).toBeInTheDocument();
    const link = within(table).getByRole('link', { name: 'Privileged container' });
    expect(link).toHaveAttribute('href', '/checks/privileged');
    expect(within(table).getByText('V-242414')).toBeInTheDocument();
    expect(within(table).getByText('AC-6')).toBeInTheDocument();

    fireEvent.change(screen.getByRole('searchbox', { name: 'Filter checks' }), { target: { value: 'liveness' } });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(2));
    expect(within(table).getByRole('link', { name: 'No liveness probe' })).toBeInTheDocument();
  });

  it('shows the empty state for an empty catalogue', async () => {
    server.use(http.get('*/api/v1/checks', () => HttpResponse.json([])));
    renderApp('/checks');
    expect(await screen.findByText('No checks')).toBeInTheDocument();
  });

  it('shows the API error with a retry', async () => {
    server.use(http.get('*/api/v1/checks', () => HttpResponse.json({ detail: 'database unavailable' }, { status: 500 })));
    renderApp('/checks');
    expect(await screen.findByText(/database unavailable/)).toBeInTheDocument();
  });
});

describe('Check detail page', () => {
  it('shows metadata, remediation and only the offenders by default', async () => {
    server.use(http.get('*/api/v1/checks/privileged', () => HttpResponse.json(DETAIL)));
    renderApp('/checks/privileged');
    expect(await screen.findByRole('heading', { name: 'Privileged container', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('Remediation')).toBeInTheDocument();
    expect(screen.getByText('Remove `privileged: true`.')).toBeInTheDocument();
    expect(screen.getByText('SV-242414r1_rule')).toBeInTheDocument();
    expect(screen.getByText('CAT I')).toBeInTheDocument();
    expect(screen.getByText('Offenders')).toBeInTheDocument();
    const table = screen.getByRole('table', { name: 'Check results' });
    expect(within(table).getAllByRole('row')).toHaveLength(3); // header + 2 failing
    expect(within(table).getByText(/system namespace/)).toBeInTheDocument();
    expect(within(table).queryByText('not privileged')).toBeNull();
  });

  it('toggles to all evaluated containers', async () => {
    const user = userEvent.setup();
    server.use(http.get('*/api/v1/checks/privileged', () => HttpResponse.json(DETAIL)));
    renderApp('/checks/privileged');
    await screen.findByText('Offenders');
    await user.click(screen.getByText('Show passing'));
    expect(await screen.findByText('All evaluated containers')).toBeInTheDocument();
    const table = screen.getByRole('table', { name: 'Check results' });
    expect(within(table).getByText('not privileged')).toBeInTheDocument();
    expect(within(table).getAllByRole('row')).toHaveLength(4);
  });

  it('shows "not mapped" for a check without a STIG rule and an empty offenders table', async () => {
    server.use(http.get('*/api/v1/checks/no-liveness-probe', () => HttpResponse.json({ ...CHECKS[1], results: [] })));
    renderApp('/checks/no-liveness-probe');
    expect(await screen.findByText('not mapped')).toBeInTheDocument();
    expect(screen.getByText('No offenders')).toBeInTheDocument();
  });

  it('shows the 404 from the API', async () => {
    renderApp('/checks/does-not-exist');
    expect(await screen.findByText(/check not found/)).toBeInTheDocument();
    const crumbs = screen.getByRole('navigation', { name: /breadcrumb/i });
    expect(within(crumbs).getByRole('link', { name: 'Posture checks' })).toHaveAttribute('href', '/checks');
  });
});
