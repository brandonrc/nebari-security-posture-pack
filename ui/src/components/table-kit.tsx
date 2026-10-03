import { ArrowDownIcon, ArrowUpDownIcon, ArrowUpIcon, ChevronLeftIcon, ChevronRightIcon, ChevronsLeftIcon, ChevronsRightIcon, SearchIcon, XIcon } from 'lucide-react';
import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router';
import { SimpleSelect } from '@/components/simple-select';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { TableCell, TableHead, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';

/** URL search params as typed page state (filters survive reload/share). */
export function useUrlState<T extends Record<string, string>>(defaults: T) {
  const [params, setParams] = useSearchParams();
  const state = Object.fromEntries(Object.entries(defaults).map(([k, v]) => [k, params.get(k) ?? v])) as T;
  const update = useCallback(
    (patch: Partial<T>, resetPage = true) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(patch)) {
            if (v === undefined || v === '' || v === defaults[k]) next.delete(k);
            else next.set(k, String(v));
          }
          if (resetPage && !('page' in patch)) next.delete('page');
          return next;
        },
        { replace: true },
      );
    },
    // defaults is a literal at call sites; stable enough
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [setParams],
  );
  return [state, update] as const;
}

export function SortableHead({
  label,
  field,
  sort,
  order,
  onSort,
  className,
}: {
  label: string;
  field: string;
  sort: string;
  order: string;
  onSort: (field: string, order: 'asc' | 'desc') => void;
  className?: string;
}) {
  const active = sort === field;
  return (
    <TableHead
      className={cn('[&_[data-slot=table-head-button]]:px-3', className)}
      aria-sort={active ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}
      onClick={() => onSort(field, active && order === 'asc' ? 'desc' : 'asc')}
    >
      {label}
      {active ? (
        order === 'asc' ? <ArrowUpIcon aria-hidden="true" className="size-3.5" /> : <ArrowDownIcon aria-hidden="true" className="size-3.5" />
      ) : (
        <ArrowUpDownIcon aria-hidden="true" className="size-3.5 text-muted-foreground" />
      )}
    </TableHead>
  );
}

export function SearchInput({ value, onChange, placeholder, label }: { value: string; onChange: (v: string) => void; placeholder: string; label: string }) {
  const [draft, setDraft] = useState(value);
  const [committed, setCommitted] = useState(value);
  // adopt external changes (e.g. "Clear filters") without an effect
  if (value !== committed) {
    setCommitted(value);
    setDraft(value);
  }
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    const t = window.setTimeout(() => {
      if (draft !== value) onChange(draft);
    }, 300);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft]);
  return (
    <div className="relative w-full sm:w-[280px]">
      <SearchIcon aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3 z-10 size-[18px] -translate-y-1/2 text-muted-foreground" />
      <Input
        aria-label={label}
        type="search"
        className="h-8 pr-9 pl-9 [&::-webkit-search-cancel-button]:hidden"
        placeholder={placeholder}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
      />
      {draft ? (
        <Button
          aria-label="Clear search"
          className="absolute top-1/2 right-1 z-10 -translate-y-1/2"
          size="icon-xs"
          variant="ghost"
          onClick={() => {
            setDraft('');
            onChange('');
          }}
        >
          <XIcon />
        </Button>
      ) : null}
    </div>
  );
}

export function Toolbar({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('flex flex-wrap items-center gap-2', className)}>{children}</div>;
}

export function Pager({
  page,
  pageSize,
  total,
  onPage,
  onPageSize,
  pageSizeOptions = [25, 50, 100, 200],
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
  onPageSize: (size: number) => void;
  pageSizeOptions?: number[];
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <p className="text-muted-foreground text-sm tabular-nums">
        {from}–{to} of {total.toLocaleString()}
      </p>
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="font-medium text-[11px] text-muted-foreground">Rows per page</span>
          <SimpleSelect
            ariaLabel="Rows per page"
            className="w-[84px]"
            value={String(pageSize)}
            onChange={(v) => onPageSize(Number(v))}
            options={pageSizeOptions.map((n) => ({ value: String(n), label: String(n) }))}
          />
        </div>
        <p className="whitespace-nowrap font-medium text-sm">
          Page {page} of {pages}
        </p>
        <div className="flex items-center gap-1">
          <Button aria-label="Go to first page" size="icon-sm" variant="outline" disabled={page <= 1} onClick={() => onPage(1)}>
            <ChevronsLeftIcon />
          </Button>
          <Button aria-label="Go to previous page" size="icon-sm" variant="outline" disabled={page <= 1} onClick={() => onPage(page - 1)}>
            <ChevronLeftIcon />
          </Button>
          <Button aria-label="Go to next page" size="icon-sm" variant="outline" disabled={page >= pages} onClick={() => onPage(page + 1)}>
            <ChevronRightIcon />
          </Button>
          <Button aria-label="Go to last page" size="icon-sm" variant="outline" disabled={page >= pages} onClick={() => onPage(pages)}>
            <ChevronsRightIcon />
          </Button>
        </div>
      </div>
    </div>
  );
}

export function SkeletonRows({ cols, rows = 6 }: { cols: number; rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, r) => (
        <TableRow key={r} aria-hidden="true">
          {Array.from({ length: cols }, (_, c) => (
            <TableCell key={c} className="h-10 px-3 py-2">
              <Skeleton className={c % 3 === 0 ? 'w-40' : c % 3 === 1 ? 'w-20' : 'w-12'} />
            </TableCell>
          ))}
        </TableRow>
      ))}
    </>
  );
}

export function StateRow({ cols, children }: { cols: number; children: ReactNode }) {
  return (
    <TableRow className="hover:bg-transparent">
      <TableCell colSpan={cols} className="p-0">
        {children}
      </TableCell>
    </TableRow>
  );
}

export const CLIENT_PAGE_SIZES = [25, 50, 100, 250];

/**
 * Client-side pagination over an already filtered + sorted list. `resetKey`
 * (e.g. the serialised filters/sort) jumps back to page 1 when it changes.
 */
export function useClientPagination<T>(rows: T[], { initialPageSize = 50, resetKey = '' }: { initialPageSize?: number; resetKey?: string } = {}) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(initialPageSize);
  const [key, setKey] = useState(resetKey);
  if (key !== resetKey) {
    setKey(resetKey);
    setPage(1);
  }
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const current = Math.min(page, pages);
  const pageRows = rows.slice((current - 1) * pageSize, current * pageSize);
  return {
    pageRows,
    pagerProps: {
      page: current,
      pageSize,
      total: rows.length,
      onPage: setPage,
      onPageSize: (n: number) => {
        setPageSize(n);
        setPage(1);
      },
      pageSizeOptions: CLIENT_PAGE_SIZES,
    },
  };
}
