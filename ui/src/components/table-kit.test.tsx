import { act, fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SearchInput } from './table-kit';

// Parent whose `value` lags behind onChange, like the URL-backed filter state: the router
// applies the search-param update in a later render than the one that emitted it.
// "Apply" stands in for the router committing the pending search param.
function Harness({ log }: { log: string[] }) {
  const [value, setValue] = useState('');
  const [pending, setPending] = useState<string | null>(null);
  return (
    <>
      <SearchInput
        label="Search images"
        placeholder="Search"
        value={value}
        onChange={(v) => {
          log.push(v);
          setPending(v);
        }}
      />
      <button
        type="button"
        onClick={() => {
          if (pending !== null) setValue(pending);
          setPending(null);
        }}
      >
        Apply
      </button>
      <button type="button" onClick={() => setValue('')}>
        Clear filters
      </button>
    </>
  );
}

describe('SearchInput', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  const setup = () => {
    const log: string[] = [];
    render(<Harness log={log} />);
    const box = screen.getByLabelText('Search images') as HTMLInputElement;
    const type = (v: string) => fireEvent.change(box, { target: { value: v } });
    const tick = (ms = 300) => act(() => vi.advanceTimersByTime(ms));
    const echo = () => fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    return { log, box, type, tick, echo };
  };

  it('debounces typing into one onChange', () => {
    const { log, type, tick, echo } = setup();
    type('traefik');
    tick(100);
    type('traefik/whoami');
    tick();
    expect(log).toEqual(['traefik/whoami']);
    echo();
    tick();
    expect(log).toEqual(['traefik/whoami']);
  });

  it('does not let the echo of its own commit overwrite a newer draft (cleared box stays cleared)', () => {
    const { log, box, type, tick, echo } = setup();
    type('traefik/whoami');
    tick();
    expect(log).toEqual(['traefik/whoami']);
    // the user clears the box before the parent has applied the first commit
    type('');
    echo();
    expect(box.value).toBe('');
    tick();
    expect(log).toEqual(['traefik/whoami', '']);
    echo();
    expect(box.value).toBe('');
  });

  it('adopts genuine external changes such as "Clear filters"', () => {
    const { log, box, type, tick, echo } = setup();
    type('nginx');
    tick();
    echo();
    expect(box.value).toBe('nginx');
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(box.value).toBe('');
    tick();
    expect(log).toEqual(['nginx']);
  });
});
