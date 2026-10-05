import { expect, shellReady, test } from './fixtures';

// Every route of the SPA (src/App.tsx), loaded directly (deep link) in mock mode.
// [path, h1 text]; the image detail h1 is the repository name.
const ROUTES: Array<[string, RegExp]> = [
  ['/', /Overview|Security posture/i],
  ['/images', /Images/],
  ['/images/img-003', /.+/],
  ['/vulnerabilities', /Vulnerabilities/],
  ['/workloads', /Workloads/],
  ['/namespaces', /Namespaces/],
  ['/checks', /Posture checks|Checks/],
  ['/checks/privileged', /Privileged container/],
  ['/supply-chain', /Supply chain/],
  ['/scans', /Scans/],
  ['/reports', /Reports/],
  ['/compliance', /Compliance/],
  ['/stig/benchmarks/disa-postgresql15', /PostgreSQL 15 STIG/],
  ['/settings', /Settings/],
  ['/no-such-page', /not found/i],
];

for (const [path, heading] of ROUTES) {
  test(`deep link ${path} renders without errors`, async ({ page, errors }) => {
    await page.goto(path);
    await shellReady(page);
    await expect(page.getByRole('heading', { level: 1 }).first()).toHaveText(heading);
    expect(errors).toEqual([]);
  });
}

test('vulnerability and scan detail pages are reachable from their lists', async ({ page }) => {
  await page.goto('/vulnerabilities');
  await shellReady(page);
  await page.getByRole('table').getByRole('link').first().click();
  await expect(page).toHaveURL(/\/vulnerabilities\/.+/);
  await shellReady(page);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/CVE-|GHSA-/);

  await page.goto('/scans');
  await shellReady(page);
  await page.getByRole('table').getByRole('link').first().click();
  await expect(page).toHaveURL(/\/scans\/.+/);
  await shellReady(page);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/Scan/);
});

test('sidebar navigation visits every section without a full reload', async ({ page }) => {
  await page.goto('/');
  await shellReady(page);
  const nav = page.getByRole('navigation', { name: 'Security Posture sections' });
  const links = nav.getByRole('link');
  const count = await links.count();
  expect(count).toBeGreaterThanOrEqual(10);
  await page.evaluate(() => ((globalThis as unknown as { __marker: boolean }).__marker = true));
  for (let i = 0; i < count; i++) {
    const link = links.nth(i);
    const href = await link.getAttribute('href');
    await link.click();
    await expect(page).toHaveURL(new RegExp(`${href === '/' ? '/$' : href}`));
    await shellReady(page);
  }
  // client-side routing: the window survived every click
  expect(await page.evaluate(() => (globalThis as unknown as { __marker?: boolean }).__marker)).toBe(true);
});
