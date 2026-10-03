import { ArrowUp, BadgeCheck, BadgeX, CircleDashed, FileCheck, FileX, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';
import type { ReactNode } from 'react';
import type { ImageProvenance, UpdateInfo, UpdateLevel } from '@/api/types';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { latestTag, updateLevel } from '@/lib/supply-chain';
import { cn } from '@/lib/utils';

type Tone = 'good' | 'warn' | 'bad' | 'none';
const TONE: Record<Tone, string> = {
  good: 'text-success-foreground',
  warn: 'text-warning-foreground',
  bad: 'text-destructive-foreground',
  none: 'text-muted-foreground',
};

function Glyph({ label, tone, icon, children }: { label: string; tone: Tone; icon: ReactNode; children: ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger
        render={<span />}
        tabIndex={0}
        aria-label={label}
        data-tone={tone}
        className={cn('inline-flex cursor-default items-center rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring [&_svg]:size-4', TONE[tone])}
      >
        {icon}
      </TooltipTrigger>
      <TooltipContent className="max-w-80">{children}</TooltipContent>
    </Tooltip>
  );
}

export function signatureState(p: ImageProvenance | null | undefined): { tone: Tone; label: string } {
  const s = p?.signature;
  if (!s) return { tone: 'none', label: 'not checked' };
  if (s.signed && s.verified) return { tone: 'good', label: 'signed and verified' };
  if (s.signed) return { tone: 'warn', label: 'signed, not verified' };
  return { tone: 'bad', label: 'unsigned' };
}

export function SignatureGlyph({ provenance }: { provenance: ImageProvenance | null | undefined }) {
  const s = provenance?.signature;
  const { tone, label } = signatureState(provenance);
  const icon = tone === 'none' ? <CircleDashed /> : tone === 'good' ? <ShieldCheck /> : tone === 'warn' ? <ShieldAlert /> : <ShieldX />;
  return (
    <Glyph label={`Signature: ${label}`} tone={tone} icon={icon}>
      <p className="font-medium">Signature · {label}</p>
      {s ? (
        <p className="text-xs opacity-80">
          signed {s.signed ? 'yes' : 'no'} · verified {s.verified ? 'yes' : 'no'}
          {s.mode ? ` · ${s.mode}` : ''}
        </p>
      ) : null}
      {s?.error ? <p className="mt-1 break-words text-xs opacity-90">{s.error}</p> : null}
    </Glyph>
  );
}

export function SbomGlyph({ provenance }: { provenance: ImageProvenance | null | undefined }) {
  const s = provenance?.sbom;
  const tone: Tone = !s ? 'none' : s.hasSBOM ? 'good' : 'bad';
  const label = !s ? 'not checked' : s.hasSBOM ? (s.format ?? 'present') : 'none attached';
  return (
    <Glyph label={`SBOM: ${label}`} tone={tone} icon={!s ? <CircleDashed /> : s.hasSBOM ? <FileCheck /> : <FileX />}>
      <p className="font-medium">SBOM · {s?.hasSBOM ? 'attached' : label}</p>
      {s?.hasSBOM && s.format ? <p className="text-xs opacity-80">format {s.format}</p> : null}
    </Glyph>
  );
}

export function ProvenanceGlyph({ provenance }: { provenance: ImageProvenance | null | undefined }) {
  const p = provenance?.provenance;
  const tone: Tone = !p ? 'none' : p.hasProvenance ? 'good' : 'bad';
  const label = !p ? 'not checked' : p.hasProvenance ? 'SLSA attestation' : 'none attached';
  return (
    <Glyph label={`Provenance: ${label}`} tone={tone} icon={!p ? <CircleDashed /> : p.hasProvenance ? <BadgeCheck /> : <BadgeX />}>
      <p className="font-medium">Provenance · {label}</p>
      {p?.predicateType ? <p className="break-all font-mono text-[11px] opacity-80">{p.predicateType}</p> : null}
      {p?.builder ? <p className="break-all text-xs opacity-80">builder {p.builder}</p> : null}
    </Glyph>
  );
}

export const UPDATE_TONE: Record<UpdateLevel, string> = {
  major: 'border-destructive-foreground/40 bg-destructive text-destructive-foreground',
  minor: 'border-warning-foreground/30 bg-warning text-warning-foreground',
  patch: 'border-info-foreground/30 bg-info text-info-foreground',
};

/** "↑ 1.2.4" chip; major behind is destructive, minor warning, patch info. */
export function UpdateIndicator({ update, className, showNone = true }: { update: UpdateInfo | null | undefined; className?: string; showNone?: boolean }) {
  const level = updateLevel(update);
  if (!update || !level) {
    if (!showNone) return null;
    return <span className="text-muted-foreground text-xs">{update ? 'up to date' : '—'}</span>;
  }
  const tag = latestTag(update);
  return (
    <Tooltip>
      <TooltipTrigger
        render={<span />}
        tabIndex={0}
        aria-label={`${level} update available: ${update.currentTag} to ${tag ?? 'newer'}`}
        data-level={level}
        className={cn(
          'inline-flex h-5 max-w-40 cursor-default items-center gap-0.5 rounded-sm border px-1 font-mono text-[11px] leading-none outline-none focus-visible:ring-2 focus-visible:ring-ring',
          UPDATE_TONE[level],
          level === 'major' && 'font-semibold',
          className,
        )}
      >
        <ArrowUp aria-hidden="true" className="size-3 shrink-0" />
        <span className="truncate">{tag ?? level}</span>
      </TooltipTrigger>
      <TooltipContent className="max-w-80">
        <p className="font-medium capitalize">{level} update available</p>
        <p className="font-mono text-xs opacity-80">
          {update.currentTag} → {tag ?? '?'}
        </p>
        {update.latestInMajor && update.newestAvailable && update.latestInMajor !== update.newestAvailable ? (
          <p className="text-xs opacity-80">latest in current major: {update.latestInMajor}</p>
        ) : null}
      </TooltipContent>
    </Tooltip>
  );
}
