import type { Page } from '@playwright/test';
import { expect, shellReady, test } from './fixtures';

/** Row count once the reports table has loaded (header + at least one report). */
async function settledRows(page: Page) {
  const rows = page.getByRole('table').getByRole('row');
  await expect(rows.nth(1)).toBeVisible();
  return rows.count();
}

test('Scan now queues a scan, shows live progress and can be cancelled', async ({ page }) => {
  await page.goto('/scans');
  await shellReady(page);
  await page.getByRole('button', { name: 'Scan now' }).click();
  await expect(page.getByText(/Scan #\d+ queued/).first()).toBeVisible();
  await expect(page.getByRole('progressbar').first()).toBeVisible();
  await expect(page.getByRole('button', { name: 'Scan now' })).toBeDisabled();
  await page.getByRole('button', { name: /Cancel/ }).click();
  await expect(page.getByText(/Scan #\d+ cancelled/).first()).toBeVisible({ timeout: 15_000 });
  await expect(page.getByRole('button', { name: 'Scan now' })).toBeEnabled();
});

test('Generate report dialog queues a report that completes', async ({ page }) => {
  await page.goto('/reports');
  await shellReady(page);
  const rowsBefore = await settledRows(page);
  await page.getByRole('button', { name: 'Generate report' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Generate report' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('combobox', { name: 'Report type' })).toBeEnabled();
  await dialog.getByRole('textbox', { name: 'System name' }).fill('e2e-system');
  await dialog.getByRole('button', { name: 'Generate' }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByText('Report queued').first()).toBeVisible();
  await expect(page.getByRole('table').getByRole('row')).toHaveCount(rowsBefore + 1);
});

test('Generate report dialog can be cancelled without queuing anything', async ({ page }) => {
  await page.goto('/reports');
  await shellReady(page);
  const rowsBefore = await settledRows(page);
  await page.getByRole('button', { name: 'Generate report' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Generate report' });
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole('table').getByRole('row')).toHaveCount(rowsBefore);
});

test('session-expired and admins-only screens (mock auth switch)', async ({ page }) => {
  await page.goto('/?mockAuth=401');
  await expect(page.getByRole('heading', { name: 'Session expired' })).toBeVisible();
  await page.goto('/?mockAuth=403');
  await expect(page.getByRole('heading', { name: 'Admins only' })).toBeVisible();
});
