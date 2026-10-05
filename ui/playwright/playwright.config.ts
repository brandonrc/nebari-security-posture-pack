import { defineConfig, devices } from '@playwright/test';

// End-to-end smoke against the mock-mode bundles (MSW in the browser): no API, no cluster.
// CI builds `dist-mock` (VITE_API_MOCK=1, the posture API) and `dist-mock-provenance`
// (VITE_API_MOCK=provenance, only provenance-collector's Go dashboard) first and runs this in
// mcr.microsoft.com/playwright:v1.63.0-noble (matches @playwright/test). `provenance.spec.ts` runs
// against the second bundle on PORT+1.
const PORT = Number(process.env.PORT ?? 4173);
const PROVENANCE_PORT = PORT + 1;
const external = Boolean(process.env.BASE_URL);

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
  projects: [
    {
      name: 'chromium',
      testIgnore: 'provenance.spec.ts',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
    },
    {
      name: 'provenance',
      testMatch: 'provenance.spec.ts',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1440, height: 900 },
        baseURL: process.env.PROVENANCE_BASE_URL ?? `http://127.0.0.1:${PROVENANCE_PORT}`,
      },
    },
  ],
  webServer: external
    ? undefined
    : [
        {
          command: `npx vite preview --outDir dist-mock --host 127.0.0.1 --port ${PORT} --strictPort`,
          cwd: '..',
          url: `http://127.0.0.1:${PORT}`,
          reuseExistingServer: !process.env.CI,
          timeout: 60_000,
        },
        {
          command: `npx vite preview --outDir dist-mock-provenance --host 127.0.0.1 --port ${PROVENANCE_PORT} --strictPort`,
          cwd: '..',
          url: `http://127.0.0.1:${PROVENANCE_PORT}`,
          reuseExistingServer: !process.env.CI,
          timeout: 60_000,
        },
      ],
});
