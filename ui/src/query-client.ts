import { MutationCache, QueryCache, QueryClient } from '@tanstack/react-query';
import { setAuthState } from '@/api/auth-state';
import { ApiError } from '@/api/client';
import { isProvenanceMode } from '@/capabilities';

function onAuthError(error: unknown) {
  if (error instanceof ApiError) {
    if (error.status === 401) setAuthState('expired');
    // provenance mode: only POST /api/scan answers 403 (not in an admin group / CSRF guard);
    // reads stay available, so the scan control toasts instead of locking the whole app
    else if (error.status === 403 && !isProvenanceMode()) setAuthState('forbidden');
  }
}

export function createQueryClient() {
  return new QueryClient({
    queryCache: new QueryCache({ onError: onAuthError }),
    mutationCache: new MutationCache({ onError: onAuthError }),
    defaultOptions: {
      queries: {
        staleTime: 15_000,
        refetchOnWindowFocus: false,
        retry: (count, error) => !(error instanceof ApiError && error.status >= 400 && error.status < 500) && count < 2,
      },
    },
  });
}
