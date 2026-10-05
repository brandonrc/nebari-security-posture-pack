import { afterEach, describe, expect, it } from 'vitest';
import { applyBranding, brandLogo, parseBranding, safeCssValue, sanitizeUrl, themeCss } from '@/branding';
import { parseConfig } from '@/config';

describe('parseBranding', () => {
  it('reads provenance-collector-pack’s branding keys', () => {
    const cfg = parseConfig({
      keycloak: { url: 'https://kc', realm: 'nebari', clientId: 'c' },
      title: 'Acme supply chain',
      logoUrl: 'https://cdn.example.com/acme.svg',
      logoUrlDark: '/branding/acme-dark.svg',
      faviconUrl: 'data:image/png;base64,iVBORw0KGgo=',
      theme: { light: { primary: 'oklch(55% 0.19 250)', primaryForeground: '#fff' }, dark: {} },
    });
    expect(cfg.title).toBe('Acme supply chain');
    expect(cfg.branding).toEqual({
      logoUrl: 'https://cdn.example.com/acme.svg',
      logoUrlDark: '/branding/acme-dark.svg',
      faviconUrl: 'data:image/png;base64,iVBORw0KGgo=',
      theme: { light: { primary: 'oklch(55% 0.19 250)', primaryForeground: '#fff' }, dark: undefined },
    });
  });

  it('drops unsafe URLs, unsafe CSS values and odd token names', () => {
    const b = parseBranding({
      logoUrl: 'javascript:alert(1)',
      logoUrlDark: '//evil.example.com/x.svg',
      faviconUrl: 'data:text/html;base64,PHNjcmlwdD4=',
      theme: { light: { primary: 'red; } body { display:none', ring: 'url(https://x)', 'bad-name': 'red', accent: 3 }, dark: 'nope' },
    });
    expect(b).toEqual({});
  });

  it('sanitizers', () => {
    expect(sanitizeUrl('')).toBeUndefined();
    expect(sanitizeUrl('not a url')).toBeUndefined();
    expect(sanitizeUrl('http://example.com/a.png')).toBe('http://example.com/a.png');
    expect(sanitizeUrl('data:image/svg+xml;base64,PHN2Zy8+')).toBe('data:image/svg+xml;base64,PHN2Zy8+');
    expect(sanitizeUrl('data:image/svg+xml,<svg/>')).toBeUndefined();
    expect(safeCssValue(' 0.5rem ')).toBe('0.5rem');
    expect(safeCssValue('expression(alert(1))')).toBeUndefined();
  });
});

describe('themeCss', () => {
  it('derives hover and sidebar tokens from primary / primaryForeground / ring unless pinned', () => {
    const css = themeCss({ light: { primary: 'blue', primaryForeground: 'white', ring: 'navy' }, dark: { primary: 'cyan', sidebarPrimary: 'teal' } });
    expect(css).toContain(':root {\n  --primary: blue;');
    expect(css).toContain('--primary-hover: color-mix(in oklch, blue 85%, black);');
    expect(css).toContain('--sidebar-primary: blue;');
    expect(css).toContain('--sidebar-primary-foreground: white;');
    expect(css).toContain('--sidebar-ring: navy;');
    expect(css).toContain('.dark {\n  --primary: cyan;\n  --sidebar-primary: teal;');
    expect(themeCss(undefined)).toBe('');
  });
});

describe('applyBranding / brandLogo', () => {
  afterEach(() => {
    document.head.querySelectorAll('style[data-branding], link[rel~="icon"]').forEach((n) => n.remove());
  });

  it('replaces the favicon and injects one theme <style>', () => {
    document.head.innerHTML += '<link rel="icon" href="/favicon.ico"><link rel="icon" href="/Nebari-Symbol.svg">';
    applyBranding({ faviconUrl: '/acme.ico', theme: { light: { primary: 'blue' } } });
    applyBranding({ faviconUrl: '/acme.ico', theme: { light: { primary: 'green' } } });
    const icons = document.head.querySelectorAll<HTMLLinkElement>('link[rel~="icon"]');
    expect([...icons].map((l) => l.getAttribute('href'))).toEqual(['/acme.ico']);
    const styles = document.head.querySelectorAll('style[data-branding]');
    expect(styles).toHaveLength(1);
    expect(styles[0].textContent).toContain('--primary: green;');
  });

  it('no branding leaves the document alone', () => {
    document.head.innerHTML += '<link rel="icon" href="/favicon.ico">';
    applyBranding({});
    expect(document.head.querySelectorAll('link[rel~="icon"]')).toHaveLength(1);
    expect(document.head.querySelector('style[data-branding]')).toBeNull();
  });

  it('picks the dark logo, then the light one, then the built-in', () => {
    expect(brandLogo({ logoUrl: '/l.svg', logoUrlDark: '/d.svg' }, true)).toBe('/d.svg');
    expect(brandLogo({ logoUrl: '/l.svg' }, true)).toBe('/l.svg');
    expect(brandLogo({ logoUrl: '/l.svg' }, false)).toBe('/l.svg');
    expect(brandLogo({ logoUrlDark: '/d.svg' }, false)).toBeNull();
    expect(brandLogo({}, true)).toBeNull();
  });
});
