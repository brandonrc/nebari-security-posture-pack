import { expect, shellReady, test } from './fixtures';

// Provenance-only mode: the `dist-mock-provenance` bundle (VITE_API_MOCK=provenance) where MSW
// plays provenance-collector-pack's Go dashboard (`/api/reports`, `/api/me`, `/api/scan`,
// `/api/export`) and `/api/v1/*` answers 404, so capability detection picks provenance mode.

const ROUTES: Array<[string, RegExp]> = [
  ['/', /^Overview$/],
  ['/images', /^Images$/],
  ['/images/busybox%3A1.36', /^busybox$/],
  ['/supply-chain', /^Supply chain$/],
  ['/scans', /^Scans$/],
  ['/reports', /^Reports$/],
];

for (const [path, heading] of ROUTES) {
  test(`provenance deep link ${path}`, async ({ page, errors }) => {
    await page.goto(path);
    await shellReady(page);
    await expect(page.getByRole('heading', { level: 1 }).first()).toHaveText(heading);
    expect(errors).toEqual([]);
  });
}

for (const path of ['/settings', '/vulnerabilities', '/compliance', '/workloads', '/checks', '/stig/benchmarks/disa-rhel9']) {
  test(`posture-only route ${path} redirects to the Overview`, async ({ page }) => {
    await page.goto(path);
    await shellReady(page);
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Overview');
  });
}

test('sidebar lists the provenance sections and navigates without a reload', async ({ page }) => {
  await page.goto('/');
  await shellReady(page);
  const nav = page.getByRole('navigation', { name: 'Security Posture sections' });
  await expect(nav.getByRole('link')).toHaveText(['Overview', 'Images', 'Supply chain', 'Reports', 'Scans']);
  await page.evaluate(() => ((globalThis as unknown as { __marker: boolean }).__marker = true));
  for (const [name, h1] of [
    ['Images', 'Images'],
    ['Supply chain', 'Supply chain'],
    ['Reports', 'Reports'],
    ['Scans', 'Scans'],
    ['Overview', 'Overview'],
  ]) {
    await nav.getByRole('link', { name }).click();
    await shellReady(page);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(h1);
  }
  expect(await page.evaluate(() => (globalThis as unknown as { __marker?: boolean }).__marker)).toBe(true);
});

test('Overview and Images render the golden report', async ({ page }) => {
  await page.goto('/');
  await shellReady(page);
  await expect(page.getByText('v0.0.0-golden')).toBeVisible();
  await expect(page.getByText('The collector reported 2 problems')).toBeVisible();
  await page.goto('/images');
  const table = page.getByRole('table', { name: 'Images' });
  await expect(table.getByRole('row')).toHaveCount(6);
  await expect(table.getByRole('columnheader', { name: 'Findings' })).toHaveCount(0);
  await table.getByRole('link', { name: 'ghcr.io/example/web:1.4.2' }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('web');
  await expect(page.getByRole('tab', { name: /Supply chain/ })).toHaveAttribute('aria-selected', 'true');
});

test('View an earlier report switches the dataset', async ({ page }) => {
  await page.goto('/reports');
  await shellReady(page);
  await page.getByRole('button', { name: 'View report provenance-20261001-120000.json' }).click();
  await expect(page.getByText('Viewing an earlier report')).toBeVisible();
  await page.getByRole('navigation', { name: 'Security Posture sections' }).getByRole('link', { name: 'Images' }).click();
  await expect(page.getByRole('table', { name: 'Images' }).getByRole('row')).toHaveCount(4);
  await page.getByRole('button', { name: 'Back to latest' }).click();
  await expect(page.getByRole('table', { name: 'Images' }).getByRole('row')).toHaveCount(6);
});

test('Run scan starts a job and adopts the new report', async ({ page }) => {
  test.setTimeout(60_000);
  await page.goto('/scans');
  await shellReady(page);
  const history = page.getByRole('table', { name: 'Scans' });
  await expect(history.getByRole('row')).toHaveCount(4);
  await page.getByRole('button', { name: 'Run scan' }).click();
  await expect(page.getByText('Scan started').first()).toBeVisible();
  await expect(page.getByLabel('Scan job status')).toContainText('provenance/manual-');
  await expect(page.getByRole('button', { name: /Scan running/ })).toBeDisabled();
  await expect(page.getByText('New report available').first()).toBeVisible({ timeout: 30_000 });
  await expect(history.getByRole('row')).toHaveCount(5);
});

test('Run scan is hidden without canRunScan', async ({ page }) => {
  await page.goto('/scans?mockAuth=viewer');
  await shellReady(page);
  await expect(page.getByText(/Manual scans are limited/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Run scan' })).toHaveCount(0);
});

test('CSV export downloads through the bearer-authenticated API', async ({ page }) => {
  await page.goto('/reports');
  await shellReady(page);
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export latest report as CSV' }).click();
  expect((await download).suggestedFilename()).toBe('provenance-report.csv');
});
