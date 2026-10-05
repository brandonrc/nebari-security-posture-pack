import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
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
