import type { ReactNode } from 'react';
import { Navigate } from 'react-router';
import { type Feature, useCapabilities } from '@/capabilities';

/** Renders `children` when the backend supports `feature`; otherwise redirects to the Overview. */
export function Gate({ feature, children }: { feature: Feature; children: ReactNode }) {
  const { features } = useCapabilities();
  return features[feature] ? children : <Navigate to="/" replace />;
}

/** Picks the page implementation for the detected backend. */
export function ByMode({ posture, provenance }: { posture: ReactNode; provenance: ReactNode }) {
  return useCapabilities().mode === 'provenance' ? provenance : posture;
}
