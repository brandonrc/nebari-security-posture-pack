/**
 * §12 supply-chain mock data: per-image provenance (keyed by ref) and Helm
 * releases. A realistic mix: upstream k8s / cert-manager / Nebari images are
 * cosign-signed (keyless) with attestations, Docker official images carry
 * BuildKit SBOM + SLSA v0.2 provenance but no signature, most third-party
 * images have nothing, and one private image couldn't be checked at all.
 */
import type { HelmRelease, ImageProvenance, UpdateInfo } from '@/api/types';

const SLSA_V1 = 'https://slsa.dev/provenance/v1';
const SLSA_V02 = 'https://slsa.dev/provenance/v0.2';
const unsigned = { signed: false, verified: false, error: 'no signatures found for image (cosign tree: 0 signatures, 0 attestations)' };
const keyless = { signed: true, verified: true, mode: 'keyless' };
const noSbom = { hasSBOM: false };
const noProv = { hasProvenance: false };
const upd = (currentTag: string, newestAvailable?: string, latestInMajor?: string): UpdateInfo => ({
  currentTag,
  newestAvailable: newestAvailable ?? currentTag,
  latestInMajor: latestInMajor ?? newestAvailable ?? currentTag,
  updateAvailable: Boolean(newestAvailable && newestAvailable !== currentTag),
});
const dockerOfficial = (tag: string, newest?: string, inMajor?: string): ImageProvenance => ({
  signature: unsigned,
  sbom: { hasSBOM: true, format: 'spdx-json' },
  provenance: { hasProvenance: true, predicateType: SLSA_V02, builder: 'https://github.com/docker-library/official-images' },
  update: upd(tag, newest, inMajor),
});

export const PROVENANCE_BY_REF: Record<string, ImageProvenance> = {
  'docker.io/library/python:3.9-slim': dockerOfficial('3.9-slim', '3.13-slim', '3.13-slim'),
  'localhost:32000/checkmaite-frontend:latest': { signature: unsigned, sbom: noSbom, provenance: noProv, update: { currentTag: 'latest', updateAvailable: false }, mutableTag: true },
  'quay.io/keycloak/keycloak:26.0.5': { signature: unsigned, sbom: noSbom, provenance: noProv, update: upd('26.0.5', '26.4.0') },
  'docker.io/bitnami/postgresql:16.4.0-debian-12-r2': {
    signature: { signed: true, verified: false, mode: 'keyless', error: 'no matching signatures: none of the expected identities matched what was in the certificate (expected issuer https://token.actions.githubusercontent.com)' },
    sbom: { hasSBOM: true, format: 'spdx-json' },
    provenance: noProv,
    update: upd('16.4.0-debian-12-r2', '17.6.0-debian-12-r0', '16.10.0-debian-12-r0'),
  },
  'quay.io/jupyterhub/k8s-hub:4.0.0': { signature: unsigned, sbom: noSbom, provenance: noProv, update: upd('4.0.0', '4.2.0') },
  'quay.io/jupyterhub/configurable-http-proxy:4.6.2': { signature: unsigned, sbom: noSbom, provenance: noProv, update: upd('4.6.2') },
  'docker.io/grafana/grafana:11.3.0': { signature: unsigned, sbom: noSbom, provenance: noProv, update: upd('11.3.0', '12.1.1', '11.6.5') },
  'docker.io/grafana/loki:3.2.0': { signature: unsigned, sbom: noSbom, provenance: noProv, update: upd('3.2.0', '3.5.3') },
  'quay.io/prometheus/prometheus:v2.55.0': { signature: unsigned, sbom: noSbom, provenance: noProv, update: upd('v2.55.0', 'v3.5.0', 'v2.55.1') },
  'quay.io/prometheus/node-exporter:v1.8.2': { signature: unsigned, sbom: noSbom, provenance: noProv, update: upd('v1.8.2', 'v1.9.1') },
  'docker.io/calico/node:v3.28.1': { signature: unsigned, sbom: noSbom, provenance: noProv, update: upd('v3.28.1', 'v3.28.2') },
  'docker.io/calico/kube-controllers:v3.28.1': { signature: unsigned, sbom: noSbom, provenance: noProv, update: upd('v3.28.1', 'v3.28.2') },
  'registry.k8s.io/coredns/coredns:v1.11.1': { signature: keyless, sbom: noSbom, provenance: noProv, update: upd('v1.11.1', 'v1.12.1') },
  'registry.k8s.io/pause:3.9': { signature: keyless, sbom: noSbom, provenance: noProv, update: upd('3.9', '3.10') },
  'docker.io/envoyproxy/gateway:v1.2.1': { signature: keyless, sbom: { hasSBOM: true, format: 'spdx-json' }, provenance: { hasProvenance: true, predicateType: SLSA_V1, builder: 'https://github.com/slsa-framework/slsa-github-generator' }, update: upd('v1.2.1', 'v1.5.0') },
  'docker.io/envoyproxy/envoy:distroless-v1.32.1': { signature: keyless, sbom: noSbom, provenance: noProv, update: { currentTag: 'distroless-v1.32.1', updateAvailable: true, latestInMajor: 'distroless-v1.35.0', newestAvailable: 'distroless-v1.35.0', level: 'minor' } },
  'quay.io/jetstack/cert-manager-controller:v1.16.1': { signature: keyless, sbom: { hasSBOM: true, format: 'spdx-json' }, provenance: { hasProvenance: true, predicateType: SLSA_V1 }, update: upd('v1.16.1', 'v1.16.5', 'v1.16.5') },
  'quay.io/nebari/nebari-landing:0.3.1': { signature: keyless, sbom: { hasSBOM: true, format: 'cyclonedx-json' }, provenance: { hasProvenance: true, predicateType: SLSA_V1, builder: 'https://github.com/actions/runner/github-hosted' }, update: upd('0.3.1') },
  'quay.io/nebari/nebari-operator:v0.1.0-alpha.20': { signature: keyless, sbom: { hasSBOM: true, format: 'cyclonedx-json' }, provenance: { hasProvenance: true, predicateType: SLSA_V1, builder: 'https://github.com/actions/runner/github-hosted' }, update: upd('v0.1.0-alpha.20') },
  'docker.io/library/redis:7.2.4': dockerOfficial('7.2.4', '8.2.1', '7.4.5'),
  'docker.io/minio/minio:RELEASE.2024-10-13T13-34-11Z': { signature: unsigned, sbom: noSbom, provenance: noProv, update: { currentTag: 'RELEASE.2024-10-13T13-34-11Z', updateAvailable: false } },
  'docker.io/longhornio/longhorn-manager:v1.7.2': { signature: unsigned, sbom: noSbom, provenance: noProv, update: upd('v1.7.2', 'v1.7.3', 'v1.7.3') },
  'docker.io/aquasec/trivy:0.75.0': { signature: keyless, sbom: { hasSBOM: true, format: 'cyclonedx-json' }, provenance: noProv, update: upd('0.75.0') },
  'quay.io/projectquay/clair:4.9.0': { signature: unsigned, sbom: noSbom, provenance: noProv, update: upd('4.9.0') },
  'docker.io/library/postgres:16-alpine': dockerOfficial('16-alpine', '17-alpine', '16-alpine'),
  'localhost:32000/security-posture-api:4c1e9a2': { signature: unsigned, sbom: noSbom, provenance: noProv, update: { currentTag: '4c1e9a2', updateAvailable: false } },
  // private image: registry auth failed, so only the signature check reported (others absent → "not checked")
  'ghcr.io/acme-internal/batch-agent:1.4.0': { signature: { signed: false, verified: false, error: 'GET https://ghcr.io/v2/acme-internal/batch-agent/manifests/sha256-…: UNAUTHORIZED: authentication required' } },
};

export const helmReleases: HelmRelease[] = [
  { releaseName: 'keycloak', namespace: 'keycloak', chart: 'keycloakx', version: '2.5.1', appVersion: '26.0.5', status: 'deployed', update: upd('2.5.1', '7.1.3', '2.6.1') },
  { releaseName: 'jupyterhub', namespace: 'jupyterhub', chart: 'jupyterhub', version: '4.0.0', appVersion: '5.2.1', status: 'deployed', update: upd('4.0.0', '4.2.0') },
  { releaseName: 'grafana', namespace: 'monitoring', chart: 'grafana', version: '8.5.2', appVersion: '11.3.0', status: 'deployed', update: upd('8.5.2', '9.4.5', '8.15.0') },
  { releaseName: 'loki', namespace: 'monitoring', chart: 'loki', version: '6.16.0', appVersion: '3.2.0', status: 'deployed', update: upd('6.16.0', '6.40.0') },
  { releaseName: 'prometheus', namespace: 'monitoring', chart: 'prometheus', version: '25.27.0', appVersion: 'v2.55.0', status: 'deployed', update: upd('25.27.0', '27.37.0', '25.30.2') },
  { releaseName: 'cert-manager', namespace: 'cert-manager', chart: 'cert-manager', version: 'v1.16.1', appVersion: 'v1.16.1', status: 'deployed', update: upd('v1.16.1', 'v1.16.5', 'v1.16.5') },
  { releaseName: 'envoy-gateway', namespace: 'envoy-gateway-system', chart: 'gateway-helm', version: 'v1.2.1', appVersion: 'v1.2.1', status: 'deployed', update: upd('v1.2.1', 'v1.5.0') },
  { releaseName: 'longhorn', namespace: 'longhorn-system', chart: 'longhorn', version: '1.7.2', appVersion: 'v1.7.2', status: 'deployed', update: upd('1.7.2', '1.7.3', '1.7.3') },
  { releaseName: 'minio', namespace: 'minio', chart: 'minio', version: '5.3.0', appVersion: 'RELEASE.2024-10-13T13-34-11Z', status: 'deployed', update: upd('5.3.0') },
  { releaseName: 'nebari-operator', namespace: 'nebari-system', chart: 'nebari-operator', version: '0.1.0-alpha.20', appVersion: 'v0.1.0-alpha.20', status: 'deployed', update: upd('0.1.0-alpha.20') },
  { releaseName: 'checkmaite', namespace: 'checkmaite', chart: 'checkmaite-pack', version: '0.4.2', appVersion: '0.4.2', status: 'failed', update: null },
  { releaseName: 'security-posture', namespace: 'security-posture', chart: 'nebari-security-posture-pack', version: '0.2.0', appVersion: '0.2.0', status: 'pending-upgrade', update: upd('0.2.0') },
];
