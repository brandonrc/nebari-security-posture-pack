import { expect, test as base, type Page } from '@playwright/test';

/** Fails the test on uncaught page errors and console errors (MSW/React warnings excluded). */
export const test = base.extend<{ errors: string[] }>({
  errors: async ({ page }, use) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
    page.on('console', (msg) => {
      if (msg.type() !== 'error') return;
      const text = msg.text();
      if (/Download the React DevTools|\[MSW\]/.test(text)) return;
      errors.push(`console: ${text}`);
    });
    await use(errors);
    expect(errors, 'no uncaught errors or console errors').toEqual([]);
  },
});

export { expect };

export async function shellReady(page: Page) {
  await expect(page.getByRole('navigation', { name: 'Security Posture sections' })).toBeVisible();
  await expect(page.getByText(/Unexpected Application Error/i)).toHaveCount(0);
  await expect(page.getByText('This page failed to load')).toHaveCount(0);
}
