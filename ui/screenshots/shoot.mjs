// Captures key pages in light and dark mode against the VITE_API_MOCK=1 build.
// Run inside mcr.microsoft.com/playwright (see ui/README.md "Screenshots").
import { chromium } from 'playwright';

const BASE = process.env.BASE_URL ?? 'http://localhost:4173';
const OUT = process.env.OUT_DIR ?? '/out';
const PAGES = [
  { name: 'overview', path: '/', ready: 'text=Cluster security posture' },
  { name: 'images', path: '/images', ready: 'table[aria-label="Images"] tbody tr:nth-child(10)' },
  { name: 'image-detail', path: '/images/img-003', ready: 'table[aria-label="Findings"] tbody tr' },
  { name: 'image-detail-supply-chain', path: '/images/img-004?tab=supply-chain', ready: 'table[aria-label="Supply-chain score deductions"]' },
  { name: 'supply-chain', path: '/supply-chain', ready: 'table[aria-label="Outdated images"] tbody tr:nth-child(5)' },
  {
    name: 'compliance-controls',
    path: '/compliance',
    ready: 'table[aria-label="Control catalog"] tbody tr:nth-child(10)',
    // expand one control to show assertion evidence
    act: async (page) => {
      await page.getByRole('button', { name: 'Show evidence for AC-12' }).click();
      await page.getByText('Raw evidence').first().click();
    },
  },
  { name: 'compliance', path: '/compliance?tab=stig', ready: 'text=CAT I open' },
  { name: 'reports', path: '/reports', ready: 'table[aria-label="Reports"] tbody tr' },
];

const browser = await chromium.launch({ args: [`--unsafely-treat-insecure-origin-as-secure=${BASE}`] });
for (const theme of ['light', 'dark']) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1, colorScheme: theme, reducedMotion: 'reduce' });
  await context.addInitScript((mode) => localStorage.setItem('nebari:themeMode', mode), theme);
  const page = await context.newPage();
  page.on('pageerror', (e) => console.error(`[${theme}] pageerror`, e.message));
  for (const p of PAGES) {
    await page.goto(`${BASE}${p.path}`, { waitUntil: 'networkidle' });
    await page.waitForSelector(p.ready, { timeout: 20000 });
    if (p.act) await p.act(page);
    await page.waitForTimeout(600);
    // the app scrolls inside <main>; grow the viewport so the whole page is captured
    const height = await page.evaluate(() => (document.querySelector('#main')?.scrollHeight ?? 1000) + 64);
    await page.setViewportSize({ width: 1440, height: Math.max(1000, height) });
    await page.waitForTimeout(300);
    const file = `${OUT}/${p.name}-${theme}.png`;
    await page.screenshot({ path: file });
    await page.setViewportSize({ width: 1440, height: 1000 });
    console.log('saved', file);
  }
  // narrow viewport check (~900px)
  await page.setViewportSize({ width: 900, height: 1000 });
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await page.waitForSelector('text=Cluster security posture');
  await page.waitForTimeout(600);
  const h900 = await page.evaluate(() => (document.querySelector('#main')?.scrollHeight ?? 1000) + 64);
  await page.setViewportSize({ width: 900, height: Math.max(1000, h900) });
  await page.waitForTimeout(300);
  await page.screenshot({ path: `${OUT}/overview-900-${theme}.png` });
  console.log('saved', `${OUT}/overview-900-${theme}.png`);
  await context.close();
}
await browser.close();
