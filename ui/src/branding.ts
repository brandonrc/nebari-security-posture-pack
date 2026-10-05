/**
 * Runtime branding from `/config.json` (provenance-collector-pack's `frontend.branding.*` chart
 * values): header logo, favicon and theme-token overrides. Every field is optional and falls back
 * to the built-in Nebari default, so an empty branding block changes nothing.
 *
 * `title` is not handled here: it is `RuntimeConfig.title` (see `productTitle`).
 */

/**
 * Theme token overrides keyed by camelCase token name (`primaryForeground`), applied as the
 * kebab-case custom property (`--primary-foreground`) on `:root` (light) or `.dark`. Only the
 * tokens documented in the chart's values.yaml are supported, but any key is passed through.
 */
export type ThemeTokens = Partial<Record<string, string>>;

export interface Branding {
  /** Header logo (light mode / default). http(s) URL, root-relative path or base64 image data URI. */
  logoUrl?: string;
  /** Dark-mode header logo; falls back to `logoUrl`, then the built-in dark logo. */
  logoUrlDark?: string;
  faviconUrl?: string;
  theme?: { light?: ThemeTokens; dark?: ThemeTokens };
}

// Rule terminators, braces, HTML chars, quotes, backslashes and url()/expression()/javascript:.
// A token value containing any of these is dropped rather than applied.
const UNSAFE_CSS = /[;<>{}"'\\]|url\s*\(|expression\s*\(|javascript:/i;
const TOKEN_NAME = /^[A-Za-z][A-Za-z0-9]*$/;

export function safeCssValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() && !UNSAFE_CSS.test(value) ? value.trim() : undefined;
}

const DATA_IMAGE = /^data:(image\/(?:png|jpe?g|svg\+xml|webp|gif|x-icon|vnd\.microsoft\.icon));base64,/i;

/** http(s) URLs, root-relative paths and base64 image data URIs; anything else → undefined. */
export function sanitizeUrl(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value.trim()) return undefined;
  const v = value.trim();
  if (v.startsWith('/') && !v.startsWith('//')) return v;
  if (DATA_IMAGE.test(v)) return v;
  try {
    const { protocol } = new URL(v);
    return protocol === 'http:' || protocol === 'https:' ? v : undefined;
  } catch {
    return undefined;
  }
}

function parseTokens(v: unknown): ThemeTokens | undefined {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return undefined;
  const out: ThemeTokens = {};
  for (const [k, raw] of Object.entries(v as Record<string, unknown>)) {
    const value = safeCssValue(raw);
    if (TOKEN_NAME.test(k) && value) out[k] = value;
  }
  return Object.keys(out).length ? out : undefined;
}

/** Reads the branding keys of a `/config.json` body; unsafe or malformed values are dropped. */
export function parseBranding(o: Record<string, unknown>): Branding {
  const theme = o.theme && typeof o.theme === 'object' ? (o.theme as Record<string, unknown>) : {};
  const light = parseTokens(theme.light);
  const dark = parseTokens(theme.dark);
  const branding: Branding = {
    logoUrl: sanitizeUrl(o.logoUrl),
    logoUrlDark: sanitizeUrl(o.logoUrlDark),
    faviconUrl: sanitizeUrl(o.faviconUrl),
    theme: light || dark ? { light, dark } : undefined,
  };
  return Object.fromEntries(Object.entries(branding).filter(([, v]) => v !== undefined)) as Branding;
}

const kebab = (s: string) => s.replace(/([A-Z])/g, '-$1').toLowerCase();

/**
 * Tokens that follow another token unless pinned: overriding `primary` alone also rebrands hover,
 * and the sidebar's active / focus states (the Nebari theme hard-codes them to magenta).
 */
function withDerived(tokens: ThemeTokens): ThemeTokens {
  const out = { ...tokens };
  if (tokens.primary) {
    out.primaryHover ??= `color-mix(in oklch, ${tokens.primary} 85%, black)`;
    out.sidebarPrimary ??= tokens.primary;
  }
  if (tokens.primaryForeground) out.sidebarPrimaryForeground ??= tokens.primaryForeground;
  if (tokens.ring) out.sidebarRing ??= tokens.ring;
  return out;
}

export function themeCss(theme: Branding['theme']): string {
  const block = (selector: string, tokens?: ThemeTokens) => {
    if (!tokens) return '';
    const decls = Object.entries(withDerived(tokens)).map(([k, v]) => `  --${kebab(k)}: ${v};`);
    return decls.length ? `${selector} {\n${decls.join('\n')}\n}\n` : '';
  };
  return block(':root', theme?.light) + block('.dark', theme?.dark);
}

/**
 * Applies favicon and theme overrides before the first render. The `<style>` is appended last to
 * `<head>` so it wins over the base tokens in index.css. Safe to call more than once.
 */
export function applyBranding(branding: Branding, doc: Document = document): void {
  if (branding.faviconUrl) {
    for (const link of doc.querySelectorAll<HTMLLinkElement>("link[rel~='icon']")) link.remove();
    const link = doc.createElement('link');
    link.rel = 'icon';
    link.href = branding.faviconUrl;
    doc.head.appendChild(link);
  }
  doc.querySelector('style[data-branding]')?.remove();
  const css = themeCss(branding.theme);
  if (css) {
    const style = doc.createElement('style');
    style.setAttribute('data-branding', '');
    style.textContent = css;
    doc.head.appendChild(style);
  }
}

/** Header logo for the current theme, or null for the built-in Nebari lockup. */
export function brandLogo(branding: Branding, isDark: boolean): string | null {
  return (isDark ? (branding.logoUrlDark ?? branding.logoUrl) : branding.logoUrl) ?? null;
}
