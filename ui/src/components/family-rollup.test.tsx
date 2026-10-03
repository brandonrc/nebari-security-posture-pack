import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { TooltipProvider } from '@/components/ui/tooltip';
import { FamilyRollupChart } from './family-rollup';

const families = [
  { family: 'AC', title: 'Access Control', implemented: 6, partial: 3, notImplemented: 1, inherited: 2, notApplicable: 0, unknown: 0 },
  { family: 'AU', title: 'Audit and Accountability', implemented: 0, partial: 2, notImplemented: 2, inherited: 2, notApplicable: 0, unknown: 1 },
  // older/partial API row: missing counters must not crash
  { family: 'SR', title: 'Supply Chain Risk Management', implemented: 1 } as never,
];

describe('FamilyRollupChart', () => {
  it('renders a legend, one row per family and labelled segments', () => {
    render(
      <TooltipProvider>
        <FamilyRollupChart families={families} />
      </TooltipProvider>,
    );
    const legend = screen.getByRole('list', { name: 'Legend' });
    for (const l of ['Implemented', 'Partial', 'Not implemented', 'Inherited', 'Unknown']) expect(within(legend).getByText(l)).toBeInTheDocument();
    const rows = within(screen.getByRole('list', { name: 'Control status by family' })).getAllByRole('listitem');
    expect(rows).toHaveLength(3);
    // zero counts produce no segment; non-zero ones are labelled with count + status
    expect(screen.getByRole('button', { name: 'AC: 6 implemented' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^AU: \d+ implemented/ })).toBeNull();
    expect(screen.getByRole('button', { name: 'AU: 1 unknown' })).toBeInTheDocument();
    expect(within(rows[0]).getByText('8')).toBeInTheDocument(); // implemented + inherited met
    expect(within(rows[2]).getByText(/\/1 met/)).toBeInTheDocument();
  });

  it('reports family and status selections', async () => {
    const onSelect = vi.fn();
    const user = userEvent.setup();
    render(
      <TooltipProvider>
        <FamilyRollupChart families={families} onSelect={onSelect} />
      </TooltipProvider>,
    );
    await user.click(screen.getByRole('button', { name: /Filter controls to family AU/ }));
    expect(onSelect).toHaveBeenLastCalledWith('AU');
    await user.click(screen.getByRole('button', { name: 'AC: 1 not implemented' }));
    expect(onSelect).toHaveBeenLastCalledWith('AC', 'not-implemented');
  });

  it('shows an empty message without families', () => {
    render(<FamilyRollupChart families={[]} />);
    expect(screen.getByText('No control families reported.')).toBeInTheDocument();
  });
});
