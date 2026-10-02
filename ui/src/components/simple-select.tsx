import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { cn } from '@/lib/utils';

export const ALL = '__all__';

export interface Option {
  value: string;
  label: string;
}

/** Thin wrapper over the Nebari Select for string-valued filters. */
export function SimpleSelect({
  value,
  onChange,
  options,
  ariaLabel,
  className,
  allLabel,
  disabled,
}: {
  value: string;
  onChange: (value: string) => void;
  options: Option[];
  ariaLabel: string;
  className?: string;
  /** When given, prepends an "all" option whose value is ''. */
  allLabel?: string;
  disabled?: boolean;
}) {
  const items = [...(allLabel ? [{ value: ALL, label: allLabel }] : []), ...options];
  return (
    <Select
      items={items}
      value={value === '' && allLabel ? ALL : value}
      disabled={disabled}
      onValueChange={(next) => onChange(next === ALL || next === null ? '' : String(next))}
    >
      <SelectTrigger aria-label={ariaLabel} className={cn('h-8 w-40', className)}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {items.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
