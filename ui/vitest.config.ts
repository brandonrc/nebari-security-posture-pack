import { defineConfig, mergeConfig } from 'vitest/config';
import viteConfig from './vite.config';

// Extends vite.config.ts (whose `test` block sets jsdom, globals and src/test/setup.ts; mergeConfig
// concatenates arrays, so do not repeat setupFiles here). Coverage gates are today's floor
// (quality review M4/M6); ratchet them up, never down.
export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      include: ['src/**/*.test.{ts,tsx}'],
      // v8 instrumentation makes the slow MSW-backed page tests ~30% slower: the 5 s default
      // failed 3/3 coverage runs.
      testTimeout: 15000,
      coverage: {
        provider: 'v8',
        include: ['src/**'],
        exclude: ['src/mocks/**', 'src/test/**', 'src/main.tsx', 'src/**/*.test.*', 'src/**/*.d.ts'],
        reporter: ['text-summary', 'lcov', 'json-summary', 'cobertura'],
        reportsDirectory: 'coverage',
        thresholds: { lines: 65, statements: 65, branches: 55, functions: 55 },
      },
    },
  }),
);
