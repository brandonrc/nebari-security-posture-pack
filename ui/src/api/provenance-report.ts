/**
 * provenance-collector-pack's dashboard contract, hand-written from
 * `schema/report.schema.json` (schemaVersion 1.x) and `internal/dashboard/{server,scan}.go`.
 * Optional here = not `required` in the schema. `src/api/provenance-adapter.test.ts` walks the
 * vendored schema (`src/mocks/fixtures/report.schema.json`) and fails when a field is added there
 * without a mapping in the adapter.
 */

export interface PcWorkloadRef {
  /** pod's controlling owner kind (ReplicaSet, StatefulSet, DaemonSet, Job, …) or `Pod` */
  kind: string;
  name: string;
}

/** Absent on an image when signature checks are disabled. */
export interface PcSignatureInfo {
  signed: boolean;
  /** verified against the configured public key; always false without a key */
  verified: boolean;
  /** why the check could not complete */
  error?: string;
}

/** Present only when an SBOM was found. */
export interface PcSbomInfo {
  hasSBOM: boolean;
  /** `spdx` | `cyclonedx` when known */
  format?: string;
}

/** Present only when SLSA provenance was found. */
export interface PcProvenanceInfo {
  hasProvenance: boolean;
  predicateType?: string;
}

/** Present only when a newer version meets the update level. */
export interface PcUpdateInfo {
  currentTag: string;
  latestInMajor?: string;
  newestAvailable?: string;
  updateAvailable: boolean;
}

export interface PcImageRecord {
  /** reference from the pod spec, as written there */
  image: string;
  /** absent when it could not be resolved (a `warnings` entry says why) */
  digest?: string;
  namespace: string;
  workload: PcWorkloadRef;
  signature?: PcSignatureInfo;
  sbom?: PcSbomInfo;
  provenance?: PcProvenanceInfo;
  update?: PcUpdateInfo;
}

export interface PcHelmRecord {
  releaseName: string;
  namespace: string;
  chart: string;
  version: string;
  appVersion: string;
  status: string;
  update?: PcUpdateInfo;
}

export interface PcReportSummary {
  totalImages: number;
  uniqueImages: number;
  signedImages: number;
  verifiedImages: number;
  imagesWithSBOM: number;
  imagesWithProvenance: number;
  imagesWithUpdates: number;
  totalHelmReleases: number;
  helmReleasesWithUpdates: number;
}

export interface PcReportMetadata {
  /** `^1\.[0-9]+\.[0-9]+$`; reports before 1.1.0 lack it */
  schemaVersion: string;
  /** RFC 3339, UTC */
  generatedAt: string;
  collectorVersion: string;
  clusterName?: string;
  namespacesScanned: string[];
}

export interface PcProvenanceReport {
  metadata: PcReportMetadata;
  images: PcImageRecord[];
  helmReleases?: PcHelmRecord[];
  summary: PcReportSummary;
  /** problems that made the report incomplete without failing the run */
  warnings?: string[];
}

/** `GET /api/reports` entry (newest first; `provenance-latest.json` is excluded). */
export interface PcReportEntry {
  filename: string;
  generatedAt: string;
  summary: PcReportSummary;
  clusterName?: string;
}

/** `GET /api/me`. Unauthenticated callers get `authEnabled` + `canRunScan: false`. */
export interface PcMe {
  authEnabled: boolean;
  email?: string;
  groups?: string[];
  canRunScan: boolean;
  features?: { timelineDeltas?: boolean };
}

/** `POST /api/scan` 200 body. */
export interface PcScanResponse {
  jobName: string;
  namespace: string;
}
