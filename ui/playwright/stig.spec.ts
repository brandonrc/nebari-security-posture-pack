import { expect, shellReady, test } from './fixtures';

// §14 SCAP views in mock mode. img-026 = security-posture-api (Ubuntu 22.04 SSG + PostgreSQL 15),
// img-011 = calico/node (RHEL 9 DISA, degraded rootfs), img-001 = python:3.9-slim (no benchmark).

test('image STIG tab: benchmark sub-tabs, header, filters and fix text', async ({ page, errors }) => {
  await page.goto('/images/img-026');
  await shellReady(page);
  await page.getByRole('tablist', { name: 'Image detail sections' }).getByRole('tab', { name: /STIG/ }).click();
  await expect(page).toHaveURL(/tab=stig/);
  const benches = page.getByRole('tablist', { name: 'Benchmarks' });
  await expect(benches.getByRole('tab')).toHaveCount(2);
  await expect(page.getByRole('heading', { name: 'Canonical Ubuntu 22.04 LTS STIG (ComplianceAsCode)' })).toBeVisible();
  await expect(page.getByLabel(/CAT I open: \d+/)).toBeVisible();

  const table = page.getByRole('table', { name: 'STIG rules' });
  await expect(table.getByRole('row')).toHaveCount(31);
  await page.getByRole('combobox', { name: 'Result' }).click();
  await page.getByRole('option', { name: 'Fail' }).click();
  await expect(table.getByRole('row').nth(1).getByText('Fail')).toBeVisible();
  const failing = await table.getByRole('row').count();
  expect(failing).toBeLessThan(31);
  await table.getByRole('button', { name: /Show fix text for/ }).first().click();
  await expect(table.getByText('Fix text')).toBeVisible();

  await benches.getByRole('tab', { name: /PostgreSQL 15 STIG/ }).click();
  await expect(page.getByRole('heading', { name: 'PostgreSQL 15 STIG' })).toBeVisible();
  await expect(page.getByText('DISA', { exact: true }).first()).toBeVisible();
  expect(errors).toEqual([]);
});

test('image STIG tab: degraded rootfs warning and the not-applicable state', async ({ page }) => {
  await page.goto('/images/img-011?tab=stig');
  await shellReady(page);
  await expect(page.getByText('Rootfs extraction was degraded')).toBeVisible();
  await page.goto('/images/img-001?tab=stig');
  await shellReady(page);
  await expect(page.getByText('No applicable benchmark', { exact: true })).toBeVisible();
});

test('Product STIGs rollup links to a benchmark page with failing rules across images', async ({ page, errors }) => {
  await page.goto('/');
  await shellReady(page);
  await page.getByTestId('stig-tile').getByRole('link', { name: /images evaluated/ }).click();
  await expect(page).toHaveURL(/\/compliance\?tab=stig#product-stigs/);
  await expect(page.getByText('Kubernetes STIG', { exact: true })).toBeVisible();
  const rollup = page.getByRole('table', { name: 'Product STIG benchmarks' });
  await expect(rollup.getByRole('row')).toHaveCount(4);
  await rollup.getByRole('link', { name: 'Red Hat Enterprise Linux 9 STIG', exact: true }).click();

  await expect(page).toHaveURL(/\/stig\/benchmarks\/disa-rhel9$/);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Red Hat Enterprise Linux 9 STIG');
  const rules = page.getByRole('table', { name: 'Benchmark rules' });
  await expect(rules.getByRole('row').nth(1)).toBeVisible();
  await rules.getByRole('button', { name: /Show images for/ }).first().click();
  const list = page.getByRole('list', { name: /Images evaluated for/ });
  await expect(list.getByRole('link').first()).toBeVisible();
  await list.getByRole('link').first().click();
  await expect(page).toHaveURL(/\/images\/img-\d+\?tab=stig/);
  await expect(page.getByRole('heading', { name: 'Red Hat Enterprise Linux 9 STIG' })).toBeVisible();
  expect(errors).toEqual([]);
});

test('images table STIG column sorts and filters', async ({ page }) => {
  await page.goto('/images');
  await shellReady(page);
  const table = page.getByRole('table', { name: 'Images' });
  await expect(table.getByTestId('stig-cell').first()).toBeVisible();
  await page.getByRole('combobox', { name: 'STIG' }).click();
  await page.getByRole('option', { name: 'STIG evaluated' }).click();
  await expect(page).toHaveURL(/stig=evaluated/);
  await expect(table.getByTestId('stig-cell')).toHaveCount(8);
  await table.getByRole('columnheader', { name: /STIG/ }).getByRole('button').click();
  await expect(page).toHaveURL(/sort=stig/);
});
