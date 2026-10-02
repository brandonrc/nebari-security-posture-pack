import { useSyncExternalStore } from 'react';

/**
 * Global auth outcome derived from API responses. Any 401 flips to `expired`
 * (session/JWT gone — reload re-enters the gateway login), any 403 to
 * `forbidden` (signed in, but not in an admin group).
 */
export type AuthState = 'ok' | 'expired' | 'forbidden';

let state: AuthState = 'ok';
const listeners = new Set<() => void>();

export function setAuthState(next: AuthState): void {
  if (state === next) return;
  // never downgrade forbidden → expired noise; an expired session wins though
  state = next;
  for (const l of listeners) l();
}

export function resetAuthState(): void {
  setAuthState('ok');
}

export function useAuthState(): AuthState {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => state,
    () => state,
  );
}
