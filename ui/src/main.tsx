import '@fontsource-variable/geist';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import './index.css';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from '@/App';
import type { AuthStrategy } from '@/auth/strategy';
import { initBackend } from '@/bootstrap';
import { productTitle } from '@/capabilities';
import { loadConfig } from '@/config';
import { createQueryClient } from '@/query-client';

/** Plain, dependency-free message so a failed login bootstrap isn't a blank page. */
function renderBootstrapError(container: HTMLElement, message: string) {
  container.textContent = '';
  const wrapper = document.createElement('div');
  wrapper.setAttribute('role', 'alert');
  wrapper.style.cssText = 'max-width:40rem;margin:4rem auto;padding:0 1.5rem;font-family:system-ui,sans-serif;line-height:1.5';
  const heading = document.createElement('h1');
  heading.textContent = 'Unable to start';
  const detail = document.createElement('p');
  detail.textContent = message;
  wrapper.append(heading, detail);
  container.append(wrapper);
}

async function bootstrap() {
  const root = document.getElementById('root') as HTMLElement;
  await loadConfig();
  const mock = import.meta.env.VITE_API_MOCK;
  let mockStrategy: AuthStrategy | undefined;
  if (mock === 'provenance') {
    const { worker, mockAuthStrategy } = await import('@/mocks/provenance-browser');
    await worker.start({ onUnhandledRequest: 'bypass', quiet: true });
    mockStrategy = mockAuthStrategy();
    console.info('[security-posture] provenance-only API mock mode (MSW) enabled');
  } else if (mock) {
    const { worker } = await import('@/mocks/browser');
    await worker.start({ onUnhandledRequest: 'bypass', quiet: true });
    console.info('[security-posture] API mock mode (MSW) enabled');
  }
  let ready: boolean;
  let capabilities;
  try {
    ({ ready, capabilities } = await initBackend({ mockStrategy }));
  } catch (err) {
    renderBootstrapError(root, 'The app could not reach the login service. Check the keycloak block in /config.json and that Keycloak is reachable, then reload.');
    throw err;
  }
  if (!ready) return; // keycloak-js is redirecting to the login page
  document.title = `${productTitle(capabilities)} · Nebari`;
  const client = createQueryClient();
  createRoot(root).render(
    <StrictMode>
      <App client={client} />
    </StrictMode>,
  );
}

void bootstrap();
