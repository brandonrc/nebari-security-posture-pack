import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { TooltipProvider } from '@/components/ui/tooltip';
import { FamilyRollupChart } from './family-rollup';

const families = [
  { family: 'AC', title: 'Access Control', passing: 6, hybrid: 0, partial: 3, failing: 1, inherited: 2, orgProvided: 0, notApplicable: 0, notAssessed: 0 },
  { family: 'AU', title: 'Audit and Accountability', passing: 0, hybrid: 0, partial: 2, failing: 2, inherited: 0, orgProvided: 2, notApplicable: 0, notAssessed: 1 },
  // older/partial API row: missing counters must not crash
  { family: 'SR', title: 'Supply Chain Risk Management', passing: 1 } as never,
];

describe('FamilyRollupChart', () => {
  it('renders a legend, one row per family and labelled segments', () => {
    render(
      <TooltipProvider>
        <FamilyRollupChart families={families} />
      </TooltipProvider>,
    );
    const legend = screen.getByRole('list', { name: 'Legend' });
    for (const l of ['Evidence passing', 'Hybrid', 'Partial', 'Failing', 'Inherited (named provider)', 'Organization-provided (unverified)', 'Not assessed'])
      expect(within(legend).getByText(l)).toBeInTheDocument();
    const rows = within(screen.getByRole('list', { name: 'Control status by family' })).getAllByRole('listitem');
    expect(rows).toHaveLength(3);
    // zero counts produce no segment; non-zero ones are labelled with count + status
    expect(screen.getByRole('button', { name: 'AC: 6 evidence passing' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^AU: \d+ evidence passing/ })).toBeNull();
    expect(screen.getByRole('button', { name: 'AU: 1 not assessed' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'AU: 2 organization-provided (unverified)' })).toBeInTheDocument();
    expect(within(rows[0]).getByText('6')).toBeInTheDocument(); // only passing counts; inherited is separate
    expect(within(rows[2]).getByText(/\/1 passing/)).toBeInTheDocument();
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
    await user.click(screen.getByRole('button', { name: 'AC: 1 failing' }));
    expect(onSelect).toHaveBeenLastCalledWith('AC', 'failing');
  });

  it('shows an empty message without families', () => {
    render(<FamilyRollupChart families={[]} />);
    expect(screen.getByText('No control families reported.')).toBeInTheDocument();
  });
});
