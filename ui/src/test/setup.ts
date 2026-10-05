import '@testing-library/jest-dom/vitest';
import { cleanup, configure } from '@testing-library/react';
import { afterAll, afterEach, beforeAll } from 'vitest';
import { resetAuthState } from '@/api/auth-state';
import { resetProvenanceState } from '@/api/provenance-adapter';
import { setScanJob } from '@/api/provenance-queries';
import { resetAuthStrategy } from '@/auth/strategy';
import { resetCapabilities } from '@/capabilities';
import { setConfig } from '@/config';
import { resetMockState } from '@/mocks/handlers';
import { resetProvenanceMock } from '@/mocks/provenance-backend';
import { server } from '@/mocks/server';

// findBy*/waitFor default to 1 s. MSW round trips plus v8 coverage on a busy runner exceed that
// now and then (findings-table and q-stig findBy calls timed out on a loaded host); a real miss
// still fails, just later.
configure({ asyncUtilTimeout: 5000 });

// jsdom gaps used by Base UI / recharts / the theme hook
if (!window.matchMedia) {
  window.matchMedia = (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }) as unknown as MediaQueryList;
}
if (!('ResizeObserver' in window)) {
  (window as unknown as { ResizeObserver: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

setConfig({ apiBase: 'http://localhost/api/v1', provenanceApiBase: 'http://localhost/api' });

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  cleanup();
  server.resetHandlers();
  resetMockState();
  resetAuthState();
  resetCapabilities();
  resetAuthStrategy();
  resetProvenanceState();
  resetProvenanceMock();
  setScanJob(null);
});
afterAll(() => server.close());
