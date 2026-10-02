const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export function formatRelative(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '—';
  const diff = now - t;
  const future = diff < 0;
  const abs = Math.abs(diff);
  let text: string;
  if (abs < MINUTE) text = 'just now';
  else if (abs < HOUR) text = `${Math.round(abs / MINUTE)}m`;
  else if (abs < DAY) text = `${Math.round(abs / HOUR)}h`;
  else if (abs < 60 * DAY) text = `${Math.round(abs / DAY)}d`;
  else text = `${Math.round(abs / (30 * DAY))}mo`;
  if (text === 'just now') return text;
  return future ? `in ${text}` : `${text} ago`;
}

/** Humanised age of a scanner DB, e.g. "5h old"; null → "unknown". */
export function formatAge(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return 'unknown';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return 'unknown';
  const abs = Math.max(0, now - t);
  if (abs < HOUR) return `${Math.max(1, Math.round(abs / MINUTE))}m old`;
  if (abs < 2 * DAY) return `${Math.round(abs / HOUR)}h old`;
  return `${Math.round(abs / DAY)} days old`;
}

export function ageHours(iso: string | null | undefined, now: number = Date.now()): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : (now - t) / HOUR;
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatShortDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || ms < 0) return '—';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)}s`;
  const m = Math.floor(s / 60);
  const rs = Math.round(s % 60);
  if (m < 60) return rs ? `${m}m ${rs}s` : `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function durationBetween(start: string | null | undefined, end: string | null | undefined, now = Date.now()): number | null {
  if (!start) return null;
  const s = Date.parse(start);
  const e = end ? Date.parse(end) : now;
  if (Number.isNaN(s) || Number.isNaN(e)) return null;
  return e - s;
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return '—';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB'];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export function formatScore(score: number | null | undefined): string {
  if (score === null || score === undefined) return '—';
  return score.toFixed(1);
}

export function shortDigest(digest: string | null | undefined): string {
  if (!digest) return '—';
  const hex = digest.replace(/^sha256:/, '');
  return `sha256:${hex.slice(0, 12)}`;
}

export function pluralize(n: number, word: string, plural = `${word}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? word : plural}`;
}

/** DataTable rows must be `Record<string, unknown>`; API interfaces are structurally fine. */
export function asRows<T extends object>(rows: T[] | undefined): Array<T & Record<string, unknown>> {
  return (rows ?? []) as Array<T & Record<string, unknown>>;
}
