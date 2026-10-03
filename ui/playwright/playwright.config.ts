import { defineConfig, devices } from '@playwright/test';

// End-to-end smoke against the mock-mode bundle (VITE_API_MOCK=1, MSW in the browser): no API,
// no cluster. CI builds `dist-mock` first (`npx vite build --outDir dist-mock` with VITE_API_MOCK=1)
// and runs this in mcr.microsoft.com/playwright:v1.63.0-noble (matches @playwright/test).
const PORT = Number(process.env.PORT ?? 4173);

export default defineConfig({
  testDir: '.',
  testMatch: '*.spec.ts',
  outputDir: '../test-results',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [['list'], ['html', { outputFolder: '../playwright-report', open: 'never' }]] : 'list',
  use: {
    baseURL: process.env.BASE_URL ?? `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } }],
  webServer: process.env.BASE_URL
    ? undefined
    : {
        command: `npx vite preview --outDir dist-mock --host 127.0.0.1 --port ${PORT} --strictPort`,
        cwd: '..',
        url: `http://127.0.0.1:${PORT}`,
        reuseExistingServer: !process.env.CI,
        timeout: 60_000,
      },
});
