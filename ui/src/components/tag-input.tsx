import { XIcon } from 'lucide-react';
import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';

/** Minimal tag input: Enter/comma adds, Backspace on empty removes last. */
export function TagInput({ value, onChange, placeholder, ariaLabel, validate }: { value: string[]; onChange: (next: string[]) => void; placeholder?: string; ariaLabel: string; validate?: (tag: string) => string | null }) {
  const [draft, setDraft] = useState('');
  const [error, setError] = useState<string | null>(null);
  const add = (raw: string) => {
    const tag = raw.trim();
    if (!tag) return;
    const problem = validate?.(tag) ?? null;
    if (problem) {
      setError(problem);
      return;
    }
    if (!value.includes(tag)) onChange([...value, tag]);
    setDraft('');
    setError(null);
  };
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex min-h-9 flex-wrap items-center gap-1.5 rounded-md border border-input bg-background px-2 py-1.5 focus-within:border-ring focus-within:ring-2 focus-within:ring-ring">
        {value.map((tag) => (
          <Badge key={tag} variant="secondary" className="gap-1 pr-1">
            {tag}
            <button type="button" aria-label={`Remove ${tag}`} className="rounded-full p-0.5 hover:bg-muted" onClick={() => onChange(value.filter((t) => t !== tag))}>
              <XIcon className="size-3" />
            </button>
          </Badge>
        ))}
        <div className="min-w-32 flex-1">
          <Input
            aria-label={ariaLabel}
            aria-invalid={error ? true : undefined}
            className="h-6 border-0 bg-transparent px-1 py-0 shadow-none focus-visible:ring-0"
            placeholder={placeholder}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onBlur={() => add(draft)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ',') {
                e.preventDefault();
                add(draft);
              } else if (e.key === 'Backspace' && !draft && value.length) {
                onChange(value.slice(0, -1));
              }
            }}
          />
        </div>
      </div>
      {error ? <p className="text-destructive-foreground text-xs">{error}</p> : null}
    </div>
  );
}
