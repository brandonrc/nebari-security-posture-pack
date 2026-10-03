import type { Baseline, ComplianceTotals, ControlCoverage, ControlStatus, FamilyRollup } from '@/api/types';
import { BASELINES } from '@/api/types';

export const CONTROL_STATUSES: ControlStatus[] = ['implemented', 'partial', 'not-implemented', 'inherited', 'not-applicable', 'unknown'];

export const CONTROL_STATUS_LABEL: Record<ControlStatus, string> = {
  implemented: 'Implemented',
  partial: 'Partial',
  'not-implemented': 'Not implemented',
  inherited: 'Inherited',
  'not-applicable': 'Not applicable',
  unknown: 'Unknown',
};

/** Map any status spelling (incl. §11 `satisfied`/`not-satisfied`, `planned`) to a ControlStatus. */
export function normalizeControlStatus(raw: string | null | undefined): ControlStatus {
  const s = (raw ?? '').toLowerCase().replace(/[_\s]+/g, '-');
  switch (s) {
    case 'implemented':
    case 'satisfied':
    case 'pass':
      return 'implemented';
    case 'partial':
    case 'partially-implemented':
      return 'partial';
    case 'not-implemented':
    case 'notimplemented':
    case 'planned':
    case 'not-satisfied':
    case 'fail':
      return 'not-implemented';
    case 'inherited':
      return 'inherited';
    case 'not-applicable':
    case 'notapplicable':
    case 'n/a':
      return 'not-applicable';
    default:
      return 'unknown';
  }
}

/** `AC-6(10)` → `AC`. */
export function familyOf(control: Pick<ControlCoverage, 'control' | 'family'>): string {
  if (control.family) return control.family.toUpperCase();
  return (control.control.split('-')[0] ?? control.control).toUpperCase();
}

export const FAMILY_TITLES: Record<string, string> = {
  AC: 'Access Control',
  AT: 'Awareness and Training',
  AU: 'Audit and Accountability',
  CA: 'Assessment, Authorization, and Monitoring',
  CM: 'Configuration Management',
  CP: 'Contingency Planning',
  IA: 'Identification and Authentication',
  IR: 'Incident Response',
  MA: 'Maintenance',
  MP: 'Media Protection',
  PE: 'Physical and Environmental Protection',
  PL: 'Planning',
  PM: 'Program Management',
  PS: 'Personnel Security',
  PT: 'PII Processing and Transparency',
  RA: 'Risk Assessment',
  SA: 'System and Services Acquisition',
  SC: 'System and Communications Protection',
  SI: 'System and Information Integrity',
  SR: 'Supply Chain Risk Management',
};

const BASELINE_RANK: Record<Baseline, number> = { low: 0, moderate: 1, high: 2 };

function asBaseline(v: string): Baseline | null {
  const s = v.toLowerCase();
  return (BASELINES as string[]).includes(s) ? (s as Baseline) : null;
}

/** Lowest baseline a control belongs to (string = lowest baseline; array = explicit list). */
export function lowestBaseline(baseline: ControlCoverage['baseline']): Baseline | null {
  if (!baseline) return null;
  const list = (Array.isArray(baseline) ? baseline : [baseline]).map(asBaseline).filter((b): b is Baseline => b !== null);
  if (!list.length) return null;
  return list.sort((a, b) => BASELINE_RANK[a] - BASELINE_RANK[b])[0];
}

/** Baselines are nested (low ⊂ moderate ⊂ high): a `low` control is in the moderate baseline. */
export function inBaseline(baseline: ControlCoverage['baseline'], target: Baseline): boolean {
  if (Array.isArray(baseline)) return baseline.some((b) => b.toLowerCase() === target);
  const lowest = lowestBaseline(baseline);
  return lowest !== null && BASELINE_RANK[lowest] <= BASELINE_RANK[target];
}

const EMPTY = { implemented: 0, partial: 0, notImplemented: 0, inherited: 0, notApplicable: 0, unknown: 0 };
const ROLLUP_KEY: Record<ControlStatus, keyof typeof EMPTY> = {
  implemented: 'implemented',
  partial: 'partial',
  'not-implemented': 'notImplemented',
  inherited: 'inherited',
  'not-applicable': 'notApplicable',
  unknown: 'unknown',
};

/** Fallback for `GET /compliance/families`: roll the control list up per family. */
export function rollupFamilies(controls: ControlCoverage[]): FamilyRollup[] {
  const map = new Map<string, FamilyRollup>();
  for (const c of controls) {
    const family = familyOf(c);
    let row = map.get(family);
    if (!row) {
      row = { family, title: FAMILY_TITLES[family] ?? family, ...EMPTY };
      map.set(family, row);
    }
    row[ROLLUP_KEY[normalizeControlStatus(c.status)]] += 1;
  }
  return [...map.values()].sort((a, b) => a.family.localeCompare(b.family));
}

/** Read a rollup row defensively (missing counters → 0). */
export function familyCounts(f: Partial<FamilyRollup>) {
  const n = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
  return {
    implemented: n(f.implemented),
    partial: n(f.partial),
    notImplemented: n(f.notImplemented),
    inherited: n(f.inherited),
    notApplicable: n(f.notApplicable),
    unknown: n(f.unknown),
  };
}

/** Overview tile: implemented / applicable controls in a baseline (inherited counts as implemented by the provider). */
export function baselineCoverage(controls: ControlCoverage[], baseline: Baseline) {
  const scoped = controls.filter((c) => inBaseline(c.baseline, baseline));
  const applicable = scoped.filter((c) => normalizeControlStatus(c.status) !== 'not-applicable');
  const implemented = applicable.filter((c) => normalizeControlStatus(c.status) === 'implemented').length;
  const inherited = applicable.filter((c) => normalizeControlStatus(c.status) === 'inherited').length;
  return { implemented, inherited, total: applicable.length };
}

export interface ControlFilter {
  q?: string;
  family?: string;
  status?: string;
  baseline?: string;
}

export function filterControls(controls: ControlCoverage[], f: ControlFilter): ControlCoverage[] {
  const q = f.q?.trim().toLowerCase();
  return controls.filter((c) => {
    if (f.family && familyOf(c) !== f.family.toUpperCase()) return false;
    if (f.status && normalizeControlStatus(c.status) !== f.status) return false;
    if (f.baseline && !inBaseline(c.baseline, f.baseline as Baseline)) return false;
    if (q) {
      const hay = `${c.control} ${c.title} ${(c.components ?? []).join(' ')} ${(c.assertions ?? []).map((a) => a.id).join(' ')}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

/** Natural order for control ids: AC-2 < AC-2(1) < AC-10. */
export function compareControlId(a: string, b: string): number {
  const parse = (id: string) => {
    const m = /^([A-Za-z]+)-(\d+)(?:\((\d+)\))?/.exec(id);
    return m ? [m[1].toUpperCase(), Number(m[2]), Number(m[3] ?? -1)] as const : [id, 0, 0] as const;
  };
  const [fa, na, ea] = parse(a);
  const [fb, nb, eb] = parse(b);
  return fa.localeCompare(fb) || na - nb || ea - eb;
}

function countTotals(controls: ControlCoverage[]): ComplianceTotals {
  const t: ComplianceTotals = { total: controls.length, ...EMPTY };
  for (const c of controls) t[ROLLUP_KEY[normalizeControlStatus(c.status)]] += 1;
  return t;
}

/**
 * Fallback for `GET /compliance/families` `totals`: the selected baseline's controls and
 * every listed control (catalog view, incl. assertion / scan-evidence controls outside it).
 */
export function complianceTotals(controls: ControlCoverage[], baseline: Baseline): { baseline: ComplianceTotals & { name: Baseline }; catalog: ComplianceTotals } {
  const scoped = controls.filter((c) => c.inBaseline ?? inBaseline(c.baseline, baseline));
  return { baseline: { name: baseline, ...countTotals(scoped) }, catalog: countTotals(controls) };
}

/** Totals as per-status counts (for status bars / tiles keyed by ControlStatus). */
export function totalsByStatus(t: ComplianceTotals): Record<ControlStatus, number> {
  return Object.fromEntries(CONTROL_STATUSES.map((s) => [s, t[ROLLUP_KEY[s]]])) as Record<ControlStatus, number>;
}

/** Controls that count towards "implemented of N": everything but not-applicable. */
export function applicableTotal(t: ComplianceTotals): number {
  return t.total - t.notApplicable;
}

/** Tooltip text with the full-catalog figure for one status (or implemented). */
export function catalogHint(t: ComplianceTotals, baselineTotal: number, status: ControlStatus): string {
  const outside = t.total - baselineTotal;
  return `Full catalog: ${t[ROLLUP_KEY[status]]} ${CONTROL_STATUS_LABEL[status].toLowerCase()} of ${t.total} controls` +
    (outside > 0 ? ` (incl. ${outside} outside the baseline)` : '');
}
