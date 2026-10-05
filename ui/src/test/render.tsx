import { render } from '@testing-library/react';
import { App } from '@/App';
import { bearerStrategy, fakeKeycloak } from '@/auth/keycloak';
import { setAuthStrategy } from '@/auth/strategy';
import { setCapabilities } from '@/capabilities';
import { MOCK_BEARER, MOCK_USER, provenanceHandlers } from '@/mocks/provenance-backend';
import { server } from '@/mocks/server';
import { createQueryClient } from '@/query-client';

export function renderApp(path = '/') {
  const client = createQueryClient();
  client.setDefaultOptions({ queries: { ...client.getDefaultOptions().queries, retry: false, refetchInterval: false } });
  return { ...render(<App client={client} initialPath={path} />), client };
}

/** Provenance-only backend: the Go dashboard mock and a signed-in keycloak-js stand-in. */
export function renderProvenanceApp(path = '/') {
  server.use(...provenanceHandlers);
  setCapabilities('provenance');
  const keycloak = fakeKeycloak(MOCK_BEARER, MOCK_USER);
  setAuthStrategy(bearerStrategy(keycloak));
  return { ...renderApp(path), keycloak };
}
