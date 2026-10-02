Scanner fixtures are trimmed copies of real output for `alpine:3.17.0`, produced on
2026-10-02 with trivy 0.75.0 (`trivy image --format json --scanners vuln`), grype 0.120.0
(`grype -o json`), and clairctl 4.9.0 (`clairctl report --out json` against Clair 4.9.0 in
combo mode, alpine updaters). Kept: CVE-2024-6119/libcrypto3, CVE-2023-0464/libssl3,
CVE-2023-42363/busybox (reported by all three) plus CVE-2022-48174/busybox (grype only).
The Clair `enrichments` entry (cvss enricher format) was added by hand.
