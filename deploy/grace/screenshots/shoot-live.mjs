// Logged-in screenshots of the live grace deployment (light mode, 1440 wide).
// Run (host network; never create a docker network on grace, see docs/DECISIONS.md):
//   docker run --rm --network host --ipc=host -u "$(id -u):$(id -g)" -e HOME=/tmp \
//     -v "$PWD/deploy/grace/screenshots":/out -v "$PWD/deploy/grace/screenshots":/work -e OUT_DIR=/out \
//     mcr.microsoft.com/playwright:v1.63.0-noble sh -c 'cd /tmp && npm i playwright@1.63.0 >/dev/null 2>&1 && cp /work/shoot-live.mjs . && node shoot-live.mjs'
import { chromium } from 'playwright';
const BASE = process.env.BASE_URL ?? 'https://security.100-89-230-107.sslip.io';
const OUT = process.env.OUT_DIR ?? '/out';
const IMAGE_ID = process.env.IMAGE_ID ?? '28';
const PAGES = [
  { name: 'overview', path: '/', ready: 'table[aria-label="Top 10 riskiest images"] tbody tr' },
  { name: 'images', path: '/images', ready: 'table[aria-label="Images"] tbody tr:nth-child(10)' },
  { name: 'image-detail', path: `/images/${IMAGE_ID}`, ready: 'table[aria-label="Findings"] tbody tr' },
  { name: 'compliance', path: '/compliance', ready: 'main table tbody tr' },
  { name: 'reports', path: '/reports', ready: 'main table tbody tr' },
  { name: 'scans', path: '/scans', ready: 'main table tbody tr' },
];
const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1, colorScheme: 'light', reducedMotion: 'reduce' });
await context.addInitScript(() => localStorage.setItem('nebari:themeMode', 'light'));
const page = await context.newPage();
page.on('pageerror', (e) => console.error('pageerror', e.message));
await page.goto(`${BASE}/`);
await page.waitForSelector('#username', { timeout: 30000 });
await page.fill('#username', process.env.KC_USER ?? 'admin');
await page.fill('#password', process.env.KC_PASS ?? 'nebari-admin');
await Promise.all([page.waitForURL((u) => u.hostname.startsWith('security.'), { timeout: 30000 }), page.click('#kc-login')]);
console.log('logged in at', page.url());
for (const p of PAGES) {
  await page.goto(`${BASE}${p.path}`, { waitUntil: 'networkidle', timeout: 60000 });
  await page.waitForSelector(p.ready, { timeout: 30000 });
  await page.waitForTimeout(1200);
  const height = await page.evaluate(() => (document.querySelector('#main')?.scrollHeight ?? 1000) + 64);
  await page.setViewportSize({ width: 1440, height: Math.min(p.name === "image-detail" ? 2400 : 4000, Math.max(1000, height)) });
  await page.waitForTimeout(400);
  await page.screenshot({ path: `${OUT}/${p.name}.png` });
  await page.setViewportSize({ width: 1440, height: 1000 });
  console.log('saved', p.name, 'height', height);
}
await browser.close();
