# Control evidence engine data: provenance

Everything here is vendored so the engine works offline. Each file states where it came from and
how faithful it is. Rebuild instructions are in the scripts named below.

| File | What | Source | Fidelity |
|---|---|---|---|
| `nist_800_53_rev5.json` | SP 800-53 rev5 catalog (ids, titles, families, implementation level, SP 800-53A leaf assessment-objective ids, statement part ids, ODP ids/labels) and the LOW / MODERATE / HIGH baselines | usnistgov/oscal-content `nist.gov/SP800-53/rev5/json` (catalog 5.2.0 and the three SP 800-53B profiles); `build_catalog.py` | Exact (trimmed) |
| `profiles/fedramp-moderate-rev5.json` | FedRAMP Rev5 Moderate baseline: 323 controls (the 287 NIST MODERATE controls + 36 FedRAMP additions) and the FedRAMP ODP values the engine checks | FedRAMP Rev5 baselines (fedramp-automation `dist/content/rev5/baselines`); transcribed 2026-10-03 from a rendering of that baseline because the GSA repository URL was unreachable | Exact control list (cross-checked against NIST MODERATE); re-verify against the FedRAMP OSCAL profile before submission |
| `profiles/cnssi-1253-mod-mod-mod.json` | DoD / NSS Moderate-Moderate-Moderate | **Approximation**: NIST MODERATE plus every rev5 control the DISA CCIs of the Kubernetes STIG V2R6 and Container Platform SRG V2R4 link to (DISA CCI list 2025-01-23). No machine-readable CNSSI 1253 baseline is published | **Not** the CNSSI 1253 Appendix D tables: overlays and NSS additions are missing. Replace the control list with the control set exported from your system in eMASS |
| `profiles/nist-odp.json` | ODP values used with the NIST LOW / MODERATE / HIGH baselines | NIST SP 800-53B assigns no ODP values; the FedRAMP Rev5 values are used as placeholders, each with its citation | Placeholder: set your organization's values (settings `controlsEngine.parameters`) |
| `components/*.yaml` | Component definitions: which platform component addresses which control, the responsibility (provider / shared / customer / org), the program's residual responsibility (CRM text), the assertions that collect evidence, evidence ceilings | Written for this pack; mappings corrected per docs/reviews/compliance-sme.md (M4) | Reviewed mapping, not an authorization |
| `../../reports/data/stig_mapping.yaml` | Kubernetes STIG V2R6 (92 rules) and Container Platform SRG V2R4 (188 rules), verbatim rule text and CCIs, plus how each rule is evaluated | DISA XCCDF zips; `api/tests/reports/build_stig_mapping.py` | Exact rule text; evaluation is ours |
| `../../reports/data/kev_snapshot.json` | CISA Known Exploited Vulnerabilities catalog (CVE -> date added, due date, ransomware use), used when the daily refresh into `CACHE_DIR/kev/` is not possible (air-gapped) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (catalog 2026.10.02); `KEV_URL` overrides the feed | Snapshot; refreshed daily by the worker / API |
| `../../reports/data/cci_rev5.json` | DISA CCI -> SP 800-53 rev5 references | DISA CCI list `U_CCI_List.xml` 2025-01-23 (rev5 references only) | Exact |

## ODP citations

Every value in `profiles/*.json` carries `control` and `source`. Summary:

| Parameter | NIST / FedRAMP Rev5 Moderate | DoD (CNSSI 1253 approximation) |
|---|---|---|
| AC-7 a failures / window | 3 in 15 min (FedRAMP AC-7 a) | 3 in 15 min (SRG-APP-000065) |
| AC-7 b lockout | 30 min or admin release (FedRAMP AC-7 b) | until released by an administrator (SRG-APP-000345) |
| AC-11 / AC-12 / SC-10 idle | 15 min (FedRAMP AC-11) | 15 min users, 10 min privileged (SRG-APP-000190) |
| IA-5(1) minimum length | 15 (SP 800-63B-4 §3.1.1.2, single-factor passwords; FedRAMP defers to 800-63B) | 15 (SRG-APP-000164) |
| AU-11 retention | 365 days active (OMB M-21-31: 12 months active, 18 months cold; FedRAMP AU-11) | 365 days (CNSSI 1253: 1 year, 5 years for SAMI; confirm your Component's value) |
