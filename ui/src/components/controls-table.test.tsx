import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it } from 'vitest';
import type { ControlCoverage } from '@/api/types';
import { TooltipProvider } from '@/components/ui/tooltip';
import type { ControlFilter } from '@/lib/controls';
import { filterControls } from '@/lib/controls';
import { ControlsTable, evidenceLine } from './controls-table';

const controls: ControlCoverage[] = [
  { control: 'AC-7', title: 'Unsuccessful Logon Attempts', family: 'AC', baseline: 'low', status: 'passing', components: ['Keycloak'], findingsOpen: 0, checksFailed: 0, assertions: [{ id: 'keycloak.brute-force-detection', title: 'Brute-force detection enabled', status: 'pass', checkedAt: new Date().toISOString(), detail: 'bruteForceProtected=true', evidence: { bruteForceProtected: true } }] },
  { control: 'AC-6', title: 'Least Privilege', family: 'AC', baseline: 'moderate', status: 'partial', components: ['Kubernetes'], findingsOpen: 0, checksFailed: 12, assertions: [] },
  { control: 'AU-2', title: 'Event Logging', family: 'AU', baseline: 'low', status: 'failing', components: ['Keycloak', 'Loki / Promtail'], findingsOpen: 0, checksFailed: 0, assertions: [{ id: 'keycloak.event-logging', title: 'Events recorded', status: 'fail', checkedAt: null, evidence: { adminEventsEnabled: false } }] },
  { control: 'SC-12(1)', title: 'Availability', family: 'SC', baseline: 'high', status: 'implemented', components: ['cert-manager'], objectives: [{ id: 'sc-12.1_obj', state: 'satisfied' }], findingsOpen: 0, checksFailed: 0 },
  // §11-only shape: no family/baseline/assertions, legacy status
  { control: 'RA-5', title: 'Vulnerability Monitoring and Scanning', findingsOpen: 140, checksFailed: 0, status: 'not-satisfied' },
];

function Harness({ initial = {} }: { initial?: ControlFilter }) {
  const [filter, setFilter] = useState<ControlFilter>(initial);
  return (
    <TooltipProvider>
      <ControlsTable controls={controls} filter={filter} onFilterChange={(p) => setFilter((f) => ({ ...f, ...p }))} />
    </TooltipProvider>
  );
}

const bodyRows = () => within(screen.getByRole('table', { name: 'Control catalog' })).getAllByRole('row').slice(1);

describe('filterControls', () => {
  it('filters by family, normalised status, nested baseline and text', () => {
    expect(filterControls(controls, { family: 'ac' }).map((c) => c.control)).toEqual(['AC-7', 'AC-6']);
    expect(filterControls(controls, { status: 'failing' }).map((c) => c.control)).toEqual(['AU-2', 'RA-5']);
    expect(filterControls(controls, { baseline: 'moderate' }).map((c) => c.control)).toEqual(['AC-7', 'AC-6', 'AU-2']);
    expect(filterControls(controls, { q: 'loki' }).map((c) => c.control)).toEqual(['AU-2']);
    expect(filterControls(controls, { q: 'brute-force' }).map((c) => c.control)).toEqual(['AC-7']);
    expect(filterControls(controls, { family: 'RA', status: 'passing' })).toEqual([]);
  });
});

describe('ControlsTable', () => {
  it('lists controls sorted by id, with legacy rows degraded gracefully', () => {
    render(<Harness />);
    expect(bodyRows().map((r) => r.getAttribute('data-control'))).toEqual(['AC-6', 'AC-7', 'AU-2', 'RA-5', 'SC-12(1)']);
    const ra5 = bodyRows()[3];
    expect(within(ra5).getByText('RA')).toBeInTheDocument();
    expect(within(ra5).getByText('Evidence failing')).toBeInTheDocument();
    expect(within(bodyRows()[4]).getByText('1 of 1 objectives')).toBeInTheDocument();
    expect(within(ra5).getByText('none')).toBeInTheDocument();
  });

  it('applies the initial family filter and the text search', async () => {
    const user = userEvent.setup();
    render(<Harness initial={{ family: 'AC' }} />);
    expect(bodyRows()).toHaveLength(2);
    await user.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(bodyRows()).toHaveLength(5);
    await user.type(screen.getByRole('searchbox', { name: 'Search controls' }), 'cert-manager');
    await waitFor(() => expect(bodyRows()).toHaveLength(1));
    expect(bodyRows()[0]).toHaveAttribute('data-control', 'SC-12(1)');
    await user.clear(screen.getByRole('searchbox', { name: 'Search controls' }));
    await user.type(screen.getByRole('searchbox', { name: 'Search controls' }), 'zzz');
    await waitFor(() => expect(screen.getByText('No controls match these filters')).toBeInTheDocument());
  });

  it('expands a row to its assertions with evidence', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Show evidence for AC-7' }));
    const list = screen.getByRole('list', { name: 'Assertions for AC-7' });
    expect(within(list).getByText('Brute-force detection enabled')).toBeInTheDocument();
    expect(within(list).getByText('bruteForceProtected=true')).toBeInTheDocument();
    expect(within(list).getByText('Raw evidence')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Show evidence for AC-6' }));
    expect(screen.getByText(/No automated assertion maps to this control/)).toBeInTheDocument();
  });

  it('sorts by failed checks', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('columnheader', { name: /^Checks/ }));
    await user.click(screen.getByRole('columnheader', { name: /^Checks/ }));
    expect(bodyRows()[0]).toHaveAttribute('data-control', 'AC-6');
  });
});

describe('evidenceLine', () => {
  it('summarises evidence objects when no detail is given', () => {
    expect(evidenceLine({ id: 'x', title: 'x', status: 'fail', evidence: { a: 1, b: [1, 2] } })).toBe('a=1 · b=[1,2]');
    expect(evidenceLine({ id: 'x', title: 'x', status: 'fail' })).toBe('—');
  });
});
