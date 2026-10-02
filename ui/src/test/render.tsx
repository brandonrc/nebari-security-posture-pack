import { render } from '@testing-library/react';
import { App } from '@/App';
import { createQueryClient } from '@/query-client';

export function renderApp(path = '/') {
  const client = createQueryClient();
  client.setDefaultOptions({ queries: { ...client.getDefaultOptions().queries, retry: false, refetchInterval: false } });
  return render(<App client={client} initialPath={path} />);
}
