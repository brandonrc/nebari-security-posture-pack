import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { checkDetail } from '@/api/normalize';
import { StatusBadge } from './posture';

describe('risk acceptances (controlsEngine.exceptions)', () => {
  it('renders accepted-risk results and risk-accepted objectives with their own label, never as pass', () => {
    render(
      <>
        <StatusBadge status="accepted-risk" />
        <StatusBadge status="risk-accepted" />
        <StatusBadge status="pass" />
      </>,
    );
    const accepted = screen.getByText('Accepted risk');
    expect(accepted.className).toMatch(/bg-warning/);
    expect(accepted.className).not.toMatch(/bg-success/);
    expect(screen.getByText('Risk accepted').className).toMatch(/border-dashed/);
  });

  it('keeps the accepted-risk count of a check separate from failed', () => {
    const c = checkDetail({ id: 'run-as-root', passed: 3, failed: 1, acceptedRisk: 2, results: [{ status: 'accepted-risk' }] });
    expect(c.failed).toBe(1);
    expect(c.acceptedRisk).toBe(2);
    expect(c.results[0]?.status).toBe('accepted-risk');
    expect(checkDetail({ id: 'x' }).acceptedRisk).toBe(0);
  });
});
