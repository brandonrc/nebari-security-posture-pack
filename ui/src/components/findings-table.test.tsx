import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { describe, expect, it } from 'vitest';
import type { Finding, ScannerName, Severity } from '@/api/types';
import { TooltipProvider } from '@/components/ui/tooltip';
import { FindingsTable } from './findings-table';

const SEVS: Severity[] = ['critical', 'high', 'medium', 'low'];
const ALL: ScannerName[] = ['trivy', 'grype', 'clair'];

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
const ok = { status: 'ok' as const, findings: 0, durationMs: 1 };

function renderTable() {
  const router = createMemoryRouter([{ path: '/', element: <FindingsTable findings={findings} scanners={{ trivy: ok, grype: ok, clair: ok }} /> }]);
  return render(
    <TooltipProvider>
      <RouterProvider router={router} />
    </TooltipProvider>,
  );
}
const bodyRows = () => within(screen.getByRole('table', { name: 'Findings' })).getAllByRole('row').slice(1);

describe('FindingsTable pagination', () => {
  it('renders 50 rows per page with the agreement summary over the full set', () => {
    renderTable();
    expect(bodyRows()).toHaveLength(50);
    expect(screen.getByText('130 of 260 flagged by all 3 scanners')).toBeInTheDocument();
    expect(screen.getByText('1–50 of 260')).toBeInTheDocument();
    expect(screen.getByText('Page 1 of 6')).toBeInTheDocument();
  });

  it('pages through sorted rows (critical first) and resizes pages', async () => {
    const user = userEvent.setup();
    renderTable();
    // default sort = severity desc: the 65 criticals fill page 1 and spill onto page 2
    expect(bodyRows().every((r) => within(r).getAllByText('Critical').length > 0)).toBe(true);
    await user.click(screen.getByRole('button', { name: 'Go to next page' }));
    expect(screen.getByText('51–100 of 260')).toBeInTheDocument();
    expect(within(bodyRows()[14]).getAllByText('Critical').length).toBeGreaterThan(0);
    expect(within(bodyRows()[15]).queryAllByText('Critical')).toHaveLength(0);
    await user.click(screen.getByRole('button', { name: 'Go to last page' }));
    expect(bodyRows()).toHaveLength(10);
  });

  it('filters before paginating and returns to page 1', async () => {
    const user = userEvent.setup();
    renderTable();
    await user.click(screen.getByRole('button', { name: 'Go to next page' }));
    await user.type(screen.getByRole('searchbox', { name: 'Search findings' }), 'CVE-2024-101');
    // CVE-2024-10100 … 10199 → 100 matches, half agreed by all three
    await waitFor(() => expect(screen.getByText('50 of 100 flagged by all 3 scanners')).toBeInTheDocument());
    expect(screen.getByText('1–50 of 100')).toBeInTheDocument();
    expect(bodyRows()).toHaveLength(50);
    await user.click(screen.getByText('Disagreements only'));
    expect(screen.getByText('0 of 50 flagged by all 3 scanners')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Go to next page' })).toBeDisabled();
  });
});
