import type { FamilyRollup } from '@/api/types';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { familyCounts } from '@/lib/controls';
import { cn } from '@/lib/utils';

/**
 * Status series for the family rollup. Status job, not identity: green/yellow/red
 * read as implemented/partial/not-implemented; inherited uses the blue chart
 * token, unknown the muted ink. Every segment also carries a text label (legend,
 * tooltip, aria-label, row total), so colour is never the only channel.
 */
export const ROLLUP_SERIES = [
  { key: 'implemented', label: 'Implemented', color: 'var(--chart-5)' },
  { key: 'partial', label: 'Partial', color: 'var(--chart-3)' },
  { key: 'notImplemented', label: 'Not implemented', color: 'var(--destructive-foreground)' },
  { key: 'inherited', label: 'Inherited', color: 'var(--chart-4)' },
  { key: 'unknown', label: 'Unknown', color: 'var(--muted-foreground)' },
] as const;

export type RollupKey = (typeof ROLLUP_SERIES)[number]['key'];

/** Rollup key → ControlStatus filter value. */
export const ROLLUP_STATUS: Record<RollupKey, string> = {
  implemented: 'implemented',
  partial: 'partial',
  notImplemented: 'not-implemented',
  inherited: 'inherited',
  unknown: 'unknown',
};

export function FamilyRollupChart({
  families,
  onSelect,
  selectedFamily,
}: {
  families: Array<Partial<FamilyRollup> & { family: string }>;
  onSelect?: (family: string, status?: string) => void;
  selectedFamily?: string;
}) {
  if (!families.length) return <p className="py-8 text-center text-muted-foreground text-sm">No control families reported.</p>;
  const rows = families.map((f) => {
    const c = familyCounts(f);
    const total = ROLLUP_SERIES.reduce((a, s) => a + c[s.key], 0);
    return { family: f.family, title: f.title ?? f.family, counts: c, total };
  });
  const max = Math.max(1, ...rows.map((r) => r.total));

  return (
    <div className="flex flex-col gap-3">
      <ul className="flex flex-wrap gap-x-4 gap-y-1 text-muted-foreground text-xs" aria-label="Legend">
        {ROLLUP_SERIES.map((s) => (
          <li key={s.key} className="inline-flex items-center gap-1.5">
            <span className="size-2.5 rounded-[3px]" style={{ background: s.color }} aria-hidden="true" />
            {s.label}
          </li>
        ))}
      </ul>
      <div role="list" aria-label="Control status by family" className="flex flex-col gap-1">
        {rows.map((r) => (
          <div
            key={r.family}
            role="listitem"
            data-family={r.family}
            className={cn(
              'grid grid-cols-[3rem_minmax(0,1fr)_5.5rem] items-center gap-3 rounded-md px-1 py-1 sm:grid-cols-[3rem_minmax(0,14rem)_minmax(0,1fr)_5.5rem]',
              selectedFamily === r.family && 'bg-muted',
            )}
          >
            <button
              type="button"
              className="w-fit rounded-sm font-medium font-mono text-sm underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
              onClick={() => onSelect?.(r.family)}
              aria-label={`Filter controls to family ${r.family} (${r.title})`}
              title={r.title}
            >
              {r.family}
            </button>
            <span className="hidden truncate text-muted-foreground text-xs sm:block" title={r.title}>
              {r.title}
            </span>
            <div className="flex h-3 gap-0.5" style={{ width: `${(r.total / max) * 100}%`, minWidth: r.total ? '0.75rem' : 0 }}>
              {r.total === 0 ? <span className="h-full w-full rounded-sm bg-muted" /> : null}
              {ROLLUP_SERIES.map((s) =>
                r.counts[s.key] ? (
                  <Tooltip key={s.key}>
                    <TooltipTrigger
                      render={<button type="button" />}
                      aria-label={`${r.family}: ${r.counts[s.key]} ${s.label.toLowerCase()}`}
                      data-series={s.key}
                      onClick={() => onSelect?.(r.family, ROLLUP_STATUS[s.key])}
                      className="h-full min-w-1 cursor-pointer rounded-[3px] outline-none hover:opacity-80 focus-visible:ring-2 focus-visible:ring-ring"
                      style={{ flexGrow: r.counts[s.key], flexBasis: 0, background: s.color }}
                    />
                    <TooltipContent>
                      <p className="font-medium">
                        {r.family} · {r.title}
                      </p>
                      <p className="text-xs tabular-nums opacity-80">
                        {r.counts[s.key]} {s.label.toLowerCase()} of {r.total}
                      </p>
                    </TooltipContent>
                  </Tooltip>
                ) : null,
              )}
            </div>
            <span className="text-right text-muted-foreground text-xs tabular-nums">
              <span className="font-medium text-foreground">{r.counts.implemented + r.counts.inherited}</span>/{r.total} met
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
