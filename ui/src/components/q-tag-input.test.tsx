import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { TagInput } from './tag-input';

function Harness({ initial = [], validate, onChange }: { initial?: string[]; validate?: (t: string) => string | null; onChange?: (v: string[]) => void }) {
  const [tags, setTags] = useState(initial);
  return (
    <TagInput
      ariaLabel="Excluded namespaces"
      placeholder="Add namespace…"
      value={tags}
      validate={validate}
      onChange={(next) => {
        setTags(next);
        onChange?.(next);
      }}
    />
  );
}

const input = () => screen.getByRole('textbox', { name: 'Excluded namespaces' });

describe('TagInput', () => {
  it('adds a trimmed tag on Enter and on comma, without duplicates', async () => {
    const user = userEvent.setup({ delay: null });
    const onChange = vi.fn();
    render(<Harness onChange={onChange} />);
    await user.type(input(), '  kube-system {Enter}');
    expect(screen.getByText('kube-system')).toBeInTheDocument();
    expect(input()).toHaveValue('');
    await user.type(input(), 'monitoring,');
    expect(screen.getByText('monitoring')).toBeInTheDocument();
    await user.type(input(), 'kube-system{Enter}');
    expect(onChange).toHaveBeenLastCalledWith(['kube-system', 'monitoring']);
    expect(screen.getAllByText('kube-system')).toHaveLength(1);
  });

  it('ignores blank input and adds the draft on blur', async () => {
    const user = userEvent.setup({ delay: null });
    const onChange = vi.fn();
    render(<Harness onChange={onChange} />);
    await user.type(input(), '   {Enter}');
    expect(onChange).not.toHaveBeenCalled();
    fireEvent.change(input(), { target: { value: 'tools' } });
    fireEvent.blur(input());
    expect(onChange).toHaveBeenCalledWith(['tools']);
  });

  it('removes tags with the remove button and Backspace on an empty draft', async () => {
    const user = userEvent.setup({ delay: null });
    render(<Harness initial={['a', 'b', 'c']} />);
    await user.click(screen.getByRole('button', { name: 'Remove b' }));
    expect(screen.queryByText('b')).toBeNull();
    await user.click(input());
    await user.keyboard('{Backspace}');
    expect(screen.queryByText('c')).toBeNull();
    expect(screen.getByText('a')).toBeInTheDocument();
    // Backspace with a draft edits the draft, not the tags
    await user.type(input(), 'x{Backspace}');
    expect(screen.getByText('a')).toBeInTheDocument();
  });

  it('shows the validation error, marks the input invalid and clears it on the next valid tag', async () => {
    const user = userEvent.setup({ delay: null });
    const validate = (t: string) => (/^[a-z0-9-]+$/.test(t) ? null : `“${t}” is not a valid namespace`);
    render(<Harness validate={validate} />);
    await user.type(input(), 'Bad_NS{Enter}');
    expect(screen.getByText('“Bad_NS” is not a valid namespace')).toBeInTheDocument();
    expect(input()).toHaveAttribute('aria-invalid', 'true');
    expect(input()).toHaveValue('Bad_NS'); // the draft is kept for correction
    await user.clear(input());
    await user.type(input(), 'good-ns{Enter}');
    expect(screen.queryByText(/is not a valid namespace/)).toBeNull();
    expect(input()).not.toHaveAttribute('aria-invalid');
    expect(screen.getByText('good-ns')).toBeInTheDocument();
  });
});
