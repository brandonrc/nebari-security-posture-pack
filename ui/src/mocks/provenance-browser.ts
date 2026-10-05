import { setupWorker } from 'msw/browser';
import { bearerStrategy, fakeKeycloak } from '@/auth/keycloak';
import type { AuthStrategy } from '@/auth/strategy';
import { MOCK_BEARER, MOCK_USER, provenanceHandlers } from './provenance-backend';

export const worker = setupWorker(...provenanceHandlers);

/** `VITE_API_MOCK=provenance`: a signed-in keycloak-js stand-in whose bearer the mock accepts. */
export function mockAuthStrategy(): AuthStrategy {
  return bearerStrategy(fakeKeycloak(MOCK_BEARER, MOCK_USER));
}
