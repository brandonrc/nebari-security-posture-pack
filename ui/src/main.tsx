import '@fontsource-variable/geist';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import './index.css';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from '@/App';
import { loadConfig } from '@/config';
import { createQueryClient } from '@/query-client';

async function bootstrap() {
  const config = await loadConfig();
  if (import.meta.env.VITE_API_MOCK) {
    const { worker } = await import('@/mocks/browser');
    await worker.start({ onUnhandledRequest: 'bypass', quiet: true });
    console.info('[security-posture] API mock mode (MSW) enabled');
  }
  document.title = `${config.title} · Nebari`;
  const client = createQueryClient();
  createRoot(document.getElementById('root') as HTMLElement).render(
    <StrictMode>
      <App client={client} />
    </StrictMode>,
  );
}

void bootstrap();
