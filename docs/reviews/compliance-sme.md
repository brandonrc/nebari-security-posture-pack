# Compliance SME review: Nebari Security Posture pack (RMF / ATO defensibility)

Reviewer stance: former ISSM, daily eMASS and STIG Viewer user. The question is whether each claim survives an SCA, a validator and an AO.
Branch `security-posture-merge`, repo `/home/geraci/work/provenance-collector-pack`. Sample artifacts: `nebari-security-posture-pack/deploy/grace/sample-reports/` (scan 5 / scan 6, grace lab, MODERATE).
This review is read-only. Nothing was modified.

## Verdict

**As a continuous-monitoring evidence collector it is good, better than most tools I've seen.** Every assertion keeps its raw evidence and a timestamp. REPORTS.md has honest caveats. The STIG defaults are mostly conservative: 86 of 92 K8s STIG rules are `Not_Reviewed`. CCIs are carried. The POA&M leaves the risk columns blank for the ISSO.

**As an ATO-artifact generator it is not defensible today.** The SSP's status semantics would be rejected in the first SCA walkthrough. The worst parts:
- "inherited" is applied to 199 of 287 MODERATE controls.
- "implemented" is granted when 1–2 configuration checks pass.
- Mappings are wrong in ways an assessor spots immediately (SC-13 from a TLS version, CM-14 from registry auth, AC-11 from an SSO timeout, AU-6 from Prometheus scraping).
- The artifacts contradict each other. In the sample SSP, **SI-2 and RA-5 are `implemented`**. The AR from the previous day marks SI-2 and RA-5 `not-satisfied`, and the POA&M carries **24,684 open items**.

Submitted as-is, the SSP could be read as misrepresenting control status. Fix the eight Must-fix items below before any program puts these files in a package.

After those fixes, the realistic and still valuable position is: *"Machine-verified evidence for platform-provided and hybrid technical controls, plus a draft Customer Responsibility Matrix."* That is achievable. A "platform SSP every program inherits" is not achievable without a separately assessed and authorized common-control-provider package.

---

## MUST-FIX (before any program uses these artifacts)

### M1. "Inherited" for organization-level controls is a misreading of NIST and will be rejected
- `controls_engine/engine.py:209-210` marks any control whose catalog prop is `implementation-level: organization` and has no assertion as `inherited`, with a generic text (`engine.py:50-51`). The default is on (`settings.py:33`).
- NIST's `implementation-level` prop says *where a control is typically implemented*. It does not mean "a common control provider has authorized it." By that prop, 224 of 287 MODERATE controls are "organization", including AC-2, IA-2, IA-5, RA-5, SI-2, SI-4, CM-6, CM-8, AU-2 and AU-6.
- The sample SSP marks these `inherited` from the organization, and many are clearly system-level or hybrid things the platform itself does or should do:
  - **IA-5** (Keycloak *is* the authenticator manager), **IA-4**, **IA-11**
  - **CM-2, CM-3, CM-5, CM-7(5)** (NIC is declarative, so this is the platform's job)
  - **CP-9 / CP-10** (backups)
  - **AC-8** (the DoD Notice and Consent banner on the Keycloak login page, a top STIG item)
  - **AC-17** (the gateway)
  - **SA-22** (unsupported components; `k8s-supported-version` literally tests it)
  - **SI-2(2)** (this pack *is* the automated flaw-status mechanism)
  - **SI-3, SI-7, SR-11** (the provenance stage verifies signatures)
  - **SC-7(4), RA-5(5), RA-5(11)**
- `ssp.py:43` then maps inherited to OSCAL `implementation-status: implemented`. That asserts implementation with no provider, no authorization and no evidence.
- An assessor will ask "inherited from *whom*, under which ATO, and where is the CCP's SSP and assessment?" There is no answer.
- **Fix:**
  - Default `inheritOrganizationalControls=false`.
  - Rename the state to `organization-provided (unverified)` or `not assessed`, and never count it toward coverage. `ui/src/pages/compliance.tsx:201` currently shows "+ N inherited" next to implemented.
  - Allow `inherited` only when a named common-control provider is configured per control: CCP system name, eMASS ID / ATO date, and the CCP's statement. Emit it as OSCAL `leveraged-authorizations` plus `inherited`.
  - Add a `hybrid` state for controls where the platform contributes part.

### M2. "Implemented" because N assertions pass ignores 800-53A determination statements
- `engine.py:192-193`: all mapped assertions pass, so the control is `implemented`. Most controls have several assessment objectives. A single setting covers one at most.
- Sample SSP examples:
  - **AC-2** `implemented` from `registrationAllowed=false`. AC-2 has parts a–l (types, managers, approvals, monitoring, notification, review, disable).
  - **CA-7** `implemented` from "scan finished < 12 h ago". CA-7 is the ConMon strategy, metrics and reporting to the AO.
  - **CA-5** `implemented` because a POA&M file was generated.
  - **AU-6** `implemented` from "Loki has logs" plus "Prometheus targets up". AU-6 is *review and analysis* of audit records.
  - **SI-4** `implemented` from Prometheus scraping. That is performance telemetry, not intrusion monitoring.
  - **SC-13** `implemented` from TLS ≥ 1.2. See M4.
- **Fix:**
  - Tag each assertion with the 800-53A objective IDs it evidences, for example `ac-7_obj.a`. The official catalog the pack vendors ("SP 800-53 Rev 5.2.0 Controls *and SP 800-53A* Assessment Procedures") contains them, but `data/build_catalog.py` trims them away.
  - Compute coverage as objectives evidenced divided by objectives total.
  - `implemented` (or better, `evidence supports satisfied`) only when every objective is either evidenced or explicitly assigned to another responsible party. Otherwise cap at `partial / evidence for n of m objectives`.

### M3. The artifacts contradict each other, and scan evidence never reaches control status
Same lab, same day:

| Control | SSP (scan 6) | OSCAL AR (scan 5) | POA&M |
|---|---|---|---|
| SI-2 | implemented ("all 2 assertions pass") | not-satisfied, 7,979 risks | 24,684 rows |
| RA-5 | implemented | not-satisfied | every vuln row = RA-5 |
| CM-2 | inherited (org) | not-satisfied (mutable-tag) | row "mutable-tag / CM-2" |
| IA-5 | inherited (org) | not-satisfied (automount-sa-token) | — |
| CM-14 | — | not-satisfied | — |

- `derive_statuses` (`engine.py:151-220`) only looks at assertions. Posture-check failures and open findings (the `findingsOpen` / `checksFailed` fields) are shown in the API but never change status.
- DESIGN §13 promises "Report `oscal-ar` now also includes assertion observations". `reports/oscal.py` has none: the 84 MB sample AR has 0 assertion observations.
- **Fix:**
  - Use one status derivation that takes assertions, posture checks and open findings (with their SLA state) as inputs.
  - Generate the SSP, AR, POA&M and SAR from the same run, and stamp each with that run/scan ID.
  - Put assertion results into the AR as observations.

### M4. Control mappings an assessor (or eMASS) will reject
The corrections below are based on the rev5 control text, the CCIs that DISA attaches to the mapped STIG/SRG rules (DoD's own linkage), and baseline membership in the vendored 5.2.0 profiles.

**Posture checks (`reports/data/controls.yaml:27-55`, duplicated at `reports/_common.py:27-44`)**

| Check | Current | Problem | Suggested |
|---|---|---|---|
| vulnerabilities | RA-5, SI-2 (+SI-2(2) if fixable) | A CVE is a SI-2 flaw. RA-5 is the *scanning* control and is evidenced as working by the finding itself. SI-2(2) is "automated mechanisms to determine flaw status"; a fix being available doesn't make it weaker. | **SI-2** primary (SI-2(c) for overdue). RA-5 only when scanning coverage fails. Drop SI-2(2) as a weakness tag (it's an *evidence* control for the pack). |
| privileged / run-as-root / privilege-escalation / caps | AC-6, CM-7 | OK | Add **SC-39** (process isolation, all baselines). run-as-root/escalation also **AC-6(8)**? (no baseline; SRG CCI-002233 maps there). Keep AC-6/CM-7. |
| host-namespaces, host-path | SC-7, CM-7 | SC-7 is boundary protection; this is host isolation. | **SC-39, AC-6, CM-7** (SRG V-233127 uses CCI-001090 → SC-4) |
| writable-rootfs | CM-6, CM-7 | Acceptable | CM-6, CM-7 (+ SI-7 integrity) |
| no-resource-limits / requests | SC-6 | SC-6 is in **no** 800-53B baseline, so eMASS will reject a POA&M against it in a MODERATE control set. | **SC-5** (DoS; SRG CCI-002385 / CCI-001095 = SC-5 / SC-5(2)) |
| mutable-tag | CM-2, CM-14 | CM-14 = signature verification before install. A digest pin is not a signature. CM-14 is in no baseline. | **CM-2, SI-7**. CM-14 only as SRG-derived (V-233065, CCI-003992) and only when signatures are actually checked. |
| no-liveness/readiness-probe | SI-13 | SI-13 is MTTF and standby components, not health probes. No baseline, so the POA&M row is unimportable. | No control (operational hygiene), or SC-5/CP-10 at most. Do **not** generate POA&M rows. |
| automount-sa-token | AC-6(10), IA-5 | AC-6(10) is about non-privileged *users* executing privileged functions. IA-5 is authenticator management (stretched). | **AC-6, CM-7** (IA-5(h) protection of authenticator content, secondary at most) |
| seccomp-unconfined | CM-6, SI-16 | SI-16 is memory protection (DEP/ASLR). Seccomp is syscall filtering. | **CM-6, CM-7, SC-39** |
| no-netpol | SC-7, AC-4 | OK | AC-4, SC-7 (SC-7(5) for default-deny) |
| provenance no-sbom | SR-4, SA-8(3), CM-8 | SA-8(3) is modular design. | SR-4, CM-8, SA-4 |
| helm-release-behind | SI-2, CM-3 | CM-3 is change control. | SI-2, **SA-22** when the release is EOL |
| update-available / major | SI-2 | Being one version behind isn't a flaw. | SA-22 when EOL. Otherwise informational. |

**Assertions (`controls_engine/assertions/*.py`, `data/components/*.yaml`)**

| Assertion | Current | Problem | Suggested |
|---|---|---|---|
| `kc-session-timeouts` (keycloak.py:111) | AC-11, AC-12 | AC-11 is *device lock* with a pattern-hiding display (the endpoint). An SSO idle timeout is not that. | **AC-12, SC-10** |
| `gw-tls-min-version` (gateway.py:146) | SC-8(1), SC-13 | SC-13 requires the *type* of cryptography the ODP specifies. For FedRAMP and DoD that means FIPS 140-validated modules. TLS ≥ 1.2 says nothing about FIPS. Ciphers are "recorded, not graded". The envoy component statement claims "restricted to modern, approved algorithms", which nothing tests. | SC-8(1) only (partial until ciphers are graded against SP 800-52r2). Drop SC-13, or add a FIPS-mode check (Envoy FIPS build / BoringCrypto). |
| `cm-certificates-valid` | SC-12, SC-12(1) | SC-12(1) is key *availability* (escrow/recovery) and is HIGH-only. | SC-12, SC-17 |
| `cm-issuer-ready` (certmanager.py:30-45) | SC-12, SC-17 | **Passes with a `selfSigned` ClusterIssuer.** The sample evidence shows "nebari-ca-issuer (ca), selfsigned-issuer (selfSigned)", so SC-17 is `implemented`. SC-17 requires an *approved* CA (DoD PKI / ECA for DoD). | Fail unless the issuer chain matches a configured approved-CA allowlist. Map IA-5(2) as well. |
| `reg-access-restricted` (registry.py:284) | CM-14, SR-4 | Registry authentication is access control, not signed components. It also *passes* an anonymous registry that is cluster-internal, so any compromised pod can push. | **AC-3, CM-5** (access restrictions for change). Require auth for push regardless of exposure. |
| `log-ingest-all-namespaces` | AU-2, AU-6, AU-12 | AU-2 is the event-selection *decision* (organizational). AU-6 is review and analysis. | **AU-12** (+ AU-6(4)/AU-9(2) as supporting) |
| `log-retention` (observability.py:114-156) | AU-4, AU-11 | **Passes when retention is disabled** ("bounded by storage"); the sample shows AU-11 `implemented`. Unbounded storage is an AU-4/AU-5 *risk*, not AU-11 evidence. | Fail or `unknown` when no retention is configured. Add an AU-4 capacity / AU-5 failure-alert assertion. |
| `mon-prometheus-scraping` | AU-6, SI-4 | Metrics aren't audit review. Performance scraping isn't SI-4 attack detection. | Supporting evidence for CA-7 / SI-4 at most. Never sufficient on its own. |
| `mon-alert-receivers` | SI-4(5), IR-6 | IR-6 is personnel reporting incidents to authorities. Any receiver, including one with no security alert rules, passes. | SI-4(5) partial (require security alert rules to exist). IR-6(1) supporting. |
| `pack-scan-recent` | RA-5, RA-5(2), CA-7 | RA-5(2) is "update vulnerabilities to be scanned" (DB freshness), not recency. CA-7 is an org program. | RA-5(a) (partial). Drop RA-5(2) and CA-7. |
| `pack-scanner-db-fresh` | RA-5(2), SI-5 | SI-5 is receiving and acting on external alerts/advisories/directives (CISA, IAVM). | RA-5(2) only |
| `pack-poam-current` | CA-5 | A file existing ≠ a POA&M that is maintained and approved. | CA-5 partial |
| `k8s-supported-version` | SI-2 | This is exactly **SA-22** (unsupported system components, all baselines). | **SA-22** (+ SI-2) |
| `k8s-cluster-admin-bindings` | AC-6(1) | OK, but AC-6(5) is closer. `is_system_subject` (kubernetes.py:93-95) whitelists *every* `system:*` User/Group, including bindings to `system:masters`-style groups or OIDC groups that lack a prefix. | AC-6(1), **AC-6(5)**. Allowlist explicit upstream system subjects only. |
| `k8s-default-sa-automount` | AC-6(10) | Same objection as above | AC-6, CM-7 |
| `k8s-default-deny-ingress` | SC-7, SC-7(5) | SC-7(5) is deny-by-default for inbound **and outbound**. Only ingress is checked. | SC-7(5) partial until egress is checked |
| `kc-self-registration-disabled` | AC-2 | One of AC-2's 12 parts | AC-2(a/f) partial |
| `kc-login-events` | AU-2, AU-12 | `enabledEventTypes` isn't checked, so the statement "records successful and failed authentication, logout, token exchange" is unverified. Retention → AU-11. | AU-12 (+ AU-11 for expiration). Check the event types. |
| `kc-password-policy` | IA-5(1) | Rev5 IA-5(1) dropped composition rules in favour of a compromised/common password list (a), long passphrases, and no forced composition. A complexity rule passes. A `passwordBlacklist` isn't required. | Require blocklist + length. DoD SRG ODP is **15** characters, not 12. |
| `kc-admin-mfa` (keycloak.py:79-108) | IA-2(1) | Checks credential *presence*, not enforcement. The docstring claims a browser-flow check that is not implemented. For DoD, privileged MFA means PKI/CAC (**IA-2(12)**, DoDI 8520.03); OTP is generally not acceptable. | Check the authentication flow. Add IA-2(2) (non-privileged) and IA-2(12) (X.509 authenticator). |
| `kc-brute-force-protection` | AC-7 | Only `failureFactor` is checked. The time window (`maxDeltaTimeSeconds`, the "15 minutes") and the lockout duration/admin release are not. | Check all AC-7 ODPs |

Also: POA&M rows tagged with controls outside the system's baseline (SC-6, SI-13, CM-14, SR-4 at MODERATE) **will fail eMASS import**. eMASS only accepts items against controls in the system's control set. Filter or remap against the selected baseline (`poam.py:232` takes `controls[0]` blindly).

### M5. Assertions that pass, or go `not-applicable`, on unsafe evidence
- **SLA clock resets per image digest.** `worker.py:568-583` keys `first_seen_at` on `(image_id, vuln_id, package)`. Rebuild or retag an image that still carries the CVE, and the clock restarts. On a fresh install everything is "first seen" today. So `pack-sla-overdue` passes on day 1 and **SI-2 shows `implemented` with 17,639 fixable findings**. Key the clock on (repository/workload, vuln, package) and keep it across digests.
- **Rule 4 in the status derivation makes controls `not-applicable` by accident.** At `engine.py:203-205`, when every mapped assertion returns NA, the control becomes NA. `kc-admin-mfa` returns NA when the admin *group name is wrong* (keycloak.py:87-88). That makes **IA-2(1) not-applicable**. `kc-admin-role-allowlist` does the same for AC-6(5). Tailoring is an AO-approved decision, never a tool inference. Map NA results to `unknown` / `not assessed`.
- `cm-issuer-ready` (selfSigned passes) and `log-retention` (disabled passes) are covered in M4.
- **Fix:** add a regression test per assertion with the "looks compliant but isn't" fixture.

### M6. STIG checklist: false closures and the SRG subset
- **V-233234** (SRG-APP-000456-CTR-001130, "updates installed within 30 days") is `NotAFinding` in the sample. The check uses first-seen-by-this-tool > 30 days, and the lab is one day old. The 30 days run from **update release**. Use the fix/advisory publish date, or emit `Not_Reviewed` when it's unknown. Listing 17,639 fixable findings under NotAFinding is indefensible.
- **V-242383** (CAT I, CNTR-K8-000290) is `NotAFinding` from *pod* inventory only. The check text runs `kubectl get all` against default, kube-public and kube-node-lease, which covers Services, ConfigMaps and other non-pod resources. The rule's own note admits these aren't inventoried. Passing should give `Not_Reviewed`. Never close a CAT I on partial evidence.
- **V-233127 / V-233163** go `NotAFinding` when no pod currently violates. The requirement is that the platform *prohibits/enforces*, and an observed absence is not enforcement. Emit NotAFinding only when `k8s-pod-security-admission` shows `restricted` enforced on every in-scope namespace; otherwise `Not_Reviewed`.
- **V-242437 / V-254800 (CAT I) `Open`** is driven by privileged pods. Because `includeSystemNamespaces` defaults to true (`_common.py:354`), privileged CNI/CSI DaemonSets in namespaces legitimately exempted by the PSA admission config will always open these CAT Is. Exclude the exempted namespaces, or list them as "verify exemption" and stay `Not_Reviewed`.
- **The SRG should not be in the checklist by default** (`includeSrg: true`).
  - DISA practice: when a product STIG exists (the Kubernetes STIG is derived from the Container Platform SRG), you assess the STIG, not the SRG.
  - A 13-rule *subset* SRG checklist is worse. eMASS and STIG Manager compute compliance from the rules present, which inflates the percentage, and the SRG findings duplicate the STIG and the POA&M.
  - Default to `false`. If a program wants the SRG (e.g. assessing Nebari itself as a container platform product), emit all rules, with unevaluated ones as `Not_Reviewed`.
- Format looks right for STIG Viewer 2.17/2.18 and 3.x. I checked:
  - ASSET element order and STIG_INFO SI_DATA names
  - the VULN_ATTRIBUTE order through CCI_REF
  - the cklb `target_data` / `stigs[].rules[]` shape and its status vocabulary
  - that CCIs are present on all rules

  I did not open the files in STIG Viewer. HOST_IP, HOST_FQDN and MAC are empty, and `HOST_NAME=nebari`. eMASS asset import and HW/SW reconciliation need real identifiers, so warn when they're blank.

### M7. Baselines and ODP defaults don't match DoD or FedRAMP, yet the docs imply they do
- Only the NIST 800-53B LOW/MOD/HIGH profiles are supported (`catalog.py:15`).
  - DoD RMF uses **CNSSI 1253** baselines (separate C/I/A, plus overlays) and DoD-specific ODPs (the DoD SRG/CCI values).
  - FedRAMP uses the **FedRAMP Rev5** baselines (Moderate ≈ 323 controls, with FedRAMP ODPs).
  - The sample SSP sets every impact level to "moderate" and uses the placeholder information type C.3.5.8 (`ssp.py:255-265`).
- `settings.py:18`, CONTROLS.md:39, DECISIONS.md:81 and ARCHITECTURE.md:150 say the defaults are "FedRAMP Moderate values". Some are not:
  - **AU-11 = 90 days** is the Rev4-era value. FedRAMP Rev5 ties AU-11 to OMB M-21-31 (12 months active, 18 months cold).
  - The **IA-5(1) 12-character minimum** is below the DoD SRG (15).
  - Privileged MFA via OTP falls short of DoD PKI requirements.
- **Fix:** ship CNSSI 1253 and FedRAMP Rev5 profiles, or state plainly "NIST 800-53B baselines only; DoD/FedRAMP tailoring required". Add per-profile ODP sets with cited sources.

### M8. Claims language that overstates the evidence
| Location | Text | Change to |
|---|---|---|
| ARCHITECTURE.md:22-24 | "becomes what SP 800-53 calls a common control provider… implements a control once, continuously proves it, and every program running on Nebari inherits it" | "can *serve as evidence source* for a common control provider. Inheritance requires the platform's controls to be assessed and authorized and documented in a CRM." |
| ARCHITECTURE.md:10-11 | "It can never say 'AC-2 is satisfied'" (implying this tool can) | Remove. No tool says a control is satisfied; an assessor does. |
| ARCHITECTURE.md:55-57 | "together they cover most of the technical controls in the MODERATE baseline" | The sample shows 21 implemented + 6 partial of 287 (≈ 27 of the 63 system-level). Say "contributes evidence to ~N controls". |
| ARCHITECTURE.md §3 diagram | "Platform SSP: common controls (implemented once, proven continuously)", listing IA-5, CM-14, SI-4, CA-7, SC-13 | Per M4, several are wrong. The engine itself reports IA-5 as org-inherited. |
| ARCHITECTURE.md §5 | "status returns to implemented" | "evidence returns to passing" |
| CONTROLS.md:130 | "Implemented by the platform: the control is satisfied by a platform setting" | "evidence from a platform setting supports the control objective(s) X" |
| DESIGN.md §13 goal | "producing an OSCAL SSP + assessment results an assessor can accept" | "…an assessor can *review*" |
| Status vocabulary (engine, UI `overview.tsx:216` "Controls implemented x/y", `family-rollup.tsx`) | implemented / inherited | "evidence: passing / partial / failing / not assessed / org-provided (unverified)" |
| Component statements stating untested facts | envoy SC-13 "cipher suites restricted…"; keycloak IA-2(1) "are required to use a second factor"; keycloak AU-2 event-type list; prometheus IR-6 "security-relevant alerts are routed"; security-posture CA-5 "A POA&M covering every open finding"; SI-5 | Reword each to what the assertion actually checks |
| SAR cover (`sar.html.j2:108,117`) | "Security Assessment Report", "Overall result: F" | The SAR is the SCA's deliverable (SP 800-37 Task A-4). Call it "Automated Assessment Summary (input to SAR)" and the grade "hygiene index", not "result". |
| UI `reports.tsx:160,201` | "One-click ATO package" / "Compliance package" | "Evidence package" |

---

## SHOULD-FIX

### S1. POA&M (`reports/poam.py`)
1. **Granularity.** One row per (image digest, CVE, package) gives 24,684 rows (7,995 unique CVEs) on a lab cluster. No ISSO will maintain that, and eMASS bulk import at that size is painful.
   - Make the default "rollup by remediation unit": one item per image/repository (the thing you rebuild), listing its CVEs in Security Checks within cell limits.
   - Offer by-CVE/weakness (closest to ACAS plugin-based POA&Ms) with Devices Affected.
   - Optionally default to CAT I/II on the POA&M, with CAT III tracked in the vuln export per local ConMon policy.
2. **Re-import creates duplicates.** POA&M Item ID is blank and the stable ID is buried in Comments, so every scan re-import creates new items. Use the eMASS REST API (POA&M `externalUid`) for create/update/close, or document a strict "import once, update by hand" workflow.
3. **Mitigations column misuse.** `poam.py:240` puts the *fix* ("Upgrade X → Y") in "Mitigations". In eMASS, Mitigations means compensating measures *already in place* that lower risk, and the AO reads it that way. Leave it blank (or "None in place") and put the fix in Milestones/Recommendations.
4. **"Mitigations (in-house and in conjunction with the Navy CSSP)"** (`poam.py:37`) is a DON-specific header. Make the eMASS layout a per-component profile (Army/Navy/AF/DISA), and default to the generic label.
5. **Severity = Raw Severity.** In eMASS, Severity is the assessed value after mitigations and threat relevance. Leave it for the ISSO, or label it clearly as unassessed. The CAT mapping (Critical/High → CAT I, Medium → II, Low → III) matches ACAS convention. OK.
6. **Office/Org is required by eMASS.** It's blank in the sample. Refuse to generate (or warn loudly) when `organization` is unset.
7. **Security Checks for configuration items** mix the internal check ID with V-IDs, and cite rules the CKL marks `Not_Reviewed` (e.g. V-242414, V-233074). Cite only V-IDs whose CKL status is Open, and add the CCIs.
8. **Boilerplate.** The identical "Impact Description" CIA sentence on every row is noise; derive it from CVSS impact metrics and workload exposure, or leave it blank. "Resources Required: no additional funding required" asserts a budget fact for the program, so mark it as a default.
9. **Overdue items carry past Scheduled Completion Dates.** Many eMASS instances reject or flag a new item whose scheduled date is in the past. Emit a Milestone Change explaining the delay, or flag those rows for ISSO action.
10. **Controls / APs.** Remap via the baseline (M4). For STIG-derived items, derive the control from the rule's CCI using the DISA CCI list, which is how eMASS links them.

### S2. SLA policy (REPORTS.md:54-73, `_common.py:20`)
- 15/30/90/180 is a blend of CISA BOD 19-02 (critical 15 / high 30 for internet-facing) and FedRAMP ConMon (Moderate 90 / Low 180; FedRAMP High-risk is 30). Document that provenance.
- For DoD, the binding dates come from **IAVM** (IAVA/IAVB compliance dates) and TASKORDs. For federal civilian systems, **CISA KEV due dates** (BOD 22-01) override severity SLAs.
- Add a KEV flag and due date, IAVM IDs where available, and record CVE publish and fix-available dates so the clock basis is selectable (discovery vs. fix release, as V-233234 requires).

### S3. OSCAL
- **SSP** (`controls_engine/ssp.py`):
  1. No `set-parameters`. The ODP values (3 failures, 900 s, 90 d…) are the first thing an assessor checks; emit them at the control-implementation level.
  2. No statement-level responses (`statements[]` per `_smt.a` …). FedRAMP and Trestle-style SSPs answer per part, and this is also how M2 gets represented.
  3. Inheritance uses a custom-ns prop (`control-origination` in `https://nebari.dev/ns/oscal`). It should use the OSCAL constructs: `system-implementation.leveraged-authorizations`, by-component `inherited` / `satisfied`, and on the provider side `export.provided` / `export.responsibility`. FedRAMP tooling expects `control-origination` in the FedRAMP namespace with its vocabulary.
  4. Inherited is mapped to `implemented` (see M1).
  5. `not-implemented → planned`: OSCAL "planned" implies a plan and date. Link it to the POA&M item, or leave the state unset.
  6. Placeholders (information types, impacts = baseline, boundary text, a single "Organization" party, no ISSO/AO roles, no diagrams) need a document-level `remarks` / draft marker so nobody submits them as-is.
  7. `import-profile` points at a raw-GitHub NIST profile. That works for Trestle resolution, but must become the FedRAMP or CNSSI profile per M7.
- **AR** (`reports/oscal.py`):
  1. `import-ap` points at a back-matter stub (oscal.py:248). Validators and tools that resolve the AP will fail. Generate a minimal real `assessment-plan`, or document the gap.
  2. Findings target `{control}_smt` with `satisfied` whenever there are no risks (oscal.py:228-239). That yields "control satisfied" from one scan check. Target objective IDs instead, and never emit `satisfied` for controls you only partially test (use `not-satisfied` or omit).
  3. The RA-5 and SI-2(2) "not-satisfied" findings come from the M4 mapping error.
  4. The AR is 84 MB with 24,668 observations. Group observations (per image/CVE) or GRC importers will choke.
  5. Assertion results are missing (M3).
  6. Risks lack `characterizations` (likelihood/impact facets) and a `risk-log`.
  7. Consider emitting the OSCAL **plan-of-action-and-milestones** model. FedRAMP is moving to machine-readable POA&Ms, and it is the natural home for these items.
- **Component definition:** usable as a starting library (Trestle can assemble SSPs from it). It lacks statements, set-params and responsibility text. PE-2/3/6/13/14 `inherited: true` sitting inside the "Kubernetes platform" component is wrong: that is the hosting CSP/facility's leveraged authorization, so model it as a separate leveraged system.

### S4. Scoring (`scoring.py`, SCORING.md)
- The A–F grade has no authoritative basis, and on the SAR cover it reads as an assessment result. Present it as an internal hygiene trend only.
- The agreement multiplier (0.6 for one scanner, `scoring.py:357`) penalises *structural coverage gaps* as if they were disagreement. Clair's language-ecosystem coverage is narrow and Grype/Trivy use different advisory sources. A KEV-listed, CVSS 10, Trivy-only finding (sample row 1) is down-weighted to 60%. Compute agreement only over scanners capable of detecting that package type, and never down-weight KEV entries.
- Container-weighted means let many clean pods mask one exposed gateway or IdP image. Unscanned images are excluded rather than penalised, which inflates the score. `SYSTEM_NAMESPACES` is `{kube-system}` in scoring (`scoring.py:362`) but three namespaces in reports (`_common.py:21`), so the two disagree.
- Add **CISA KEV** (binary, with due date: automatic F or a separate "KEV exposure" tile) and **EPSS** percentile for ordering the POA&M and remediation queue. Show the CVSS version, vector and source; consensus severity is the max of vendor severities, not NVD CVSS, and DoD CAT mapping is CVSS-based. VPR is Tenable-proprietary and not needed. For DoD, an IAVM cross-reference matters more than any of these.

### S5. Assertion depth (beyond M4/M5)
- AC-7: check the window and the lockout duration (admin release for DoD).
- SC-7(5): check egress.
- AU-2/AU-12: check `enabledEventTypes`.
- Cluster-admin: also flag wildcard `*` verbs/resources roles and `escalate`/`bind`/`impersonate` grants.
- K8s EOL: the upstream table is wrong for distros (MicroK8s, RKE2, OpenShift, EKS have their own support windows).
- `kc-ssl-required=external`: behind the gateway Keycloak sees a private proxy IP, so "external" effectively allows HTTP on internal hops.

### S6. Hybrid controls and responsibility
Add a per-control `responsibility` field (provider / shared / customer / org-CCP) with customer-responsibility text. That field is the CRM; see section 8.

---

## NICE

- **N1.** Derive NIST tags for STIG-derived items from the rule's CCIs via DISA's CCI list (rev5 mappings), so the pack, eMASS and STIG Manager agree by construction. Examples: CCI-002233 → AC-6(8), CCI-001090 → SC-4, CCI-002385 → SC-5, CCI-002605 → SI-2(c), CCI-001813 → CM-5(1), CCI-003992 → CM-14.
- **N2.** Feed controls-engine evidence into the K8s STIG checklist. Anonymous RBAC, PSA labels and kubeadm audit flags could close or open some of the 86 `Not_Reviewed` rules with real evidence.
- **N3.** High-value assertions the platform can genuinely own:
  - AC-8 DoD banner on the Keycloak login theme
  - IA-2(12) X.509/CAC authenticator flow
  - CP-9 (Velero/Longhorn backup recency)
  - SI-7 / CM-14 (admission-time signature enforcement via Kyverno or sigstore policy-controller)
  - CM-7(5) (registry allowlist admission policy)
  - CM-2 / CM-3 (GitOps drift = 0)
  - SA-22 (EOL base OS from scanner metadata)
  - SC-28 (etcd encryption-at-rest, encrypted StorageClasses)
  - AU-5 (log-pipeline failure alerting)
  - SI-4 (runtime detection such as Falco or Tetragon present and alerting)
  - SC-10
- **N4.** eMASS-native outputs:
  - Test Results import (by CCI/AP, via API `test-results`)
  - Implementation Plan import
  - HW/SW list import format

  eMASS does not treat an OSCAL SSP as the system of record, so DoD programs need these more than OSCAL.
- **N5.** Notify inheriting systems when a provided control's evidence regresses (cATO inheritance hygiene).
- **N6.** Let ISSO VEX decisions (not_affected / false_positive, with justification) flow back to suppress POA&M rows. Today every VEX entry is `in_triage`.

---

## 8. The "platform as common-control provider" thesis

**How an AO and SCA actually treat it.** Under SP 800-37 Rev 2 (Tasks P-5, S-2, A-*, R-*) and DoDI 8510.01:
- A common control provider is an organizational entity whose common controls are documented in *its own* security plan, assessed by an independent SCA, and authorized.
- In DoD, that means the platform is registered in eMASS as its own system, often as a CCP. It gets its own ATO, or is assessed inside the hosting enclave's ATO, and it publishes inheritable controls in eMASS.
- The program system then *inherits* (or marks hybrid) by linking to that record. The CCP's compliance status and POA&Ms flow through the inheritance relationship.
- Platform One / Party Bus and the FedRAMP-authorized CSPs work this way.

A machine-generated SSP refreshed every 6 hours does not substitute for that. The AO authorizes a *state plus a ConMon strategy*, not a live feed.

**Artifacts needed to make inheritance real:**
1. A **platform SSP** for the CCP boundary (Nebari platform services as deployed by NIC), with ODPs set. It is assessed (SAR by an independent SCA) and authorized (ATO letter), with its own POA&M and ConMon plan.
2. A **Customer Responsibility Matrix (CRM)**: per control and statement, *Provided* (fully inheritable), *Shared/Hybrid* (with the program's residual responsibility written out), or *Customer*. Formats: FedRAMP's CIS/CRM workbook, or the OSCAL `export.provided` / `export.responsibility` statements.
3. **Inheritance configuration** in eMASS (or OSCAL `leveraged-authorizations` plus by-component `inherited` / `satisfied` in the program SSP), so the program's SSP references the provider's authorization rather than re-asserting it.
4. An **interconnection/reciprocity basis** (the same AO, or DoD reciprocity) and an agreed ConMon reporting cadence to tenants. This pack's evidence feed is a strong fit for that last item.
5. **Tenant-configuration guardrails.** Several "platform" controls are really tenant-configured: NebariApp `auth.groups`, `enforceAtGateway:false` exceptions, per-namespace NetworkPolicies. They are hybrid at best unless admission policy enforces them.

**Realistic ceiling at MODERATE (287 controls).** These are my estimates, not measurements:
- **Fully provided by a K8s platform like this: about 15–30 controls (roughly 5–10%).** Gateway TLS (SC-8/8(1)), SC-23, SC-12/SC-17 (with an approved CA), AC-7/AC-11/AC-12/SC-10 via the shared IdP, AC-14, SC-39, SA-22 for platform components, CM-8(1) for container inventory, RA-5/RA-5(2) for images, AU-12 for platform logs, and the physical controls through the hosting CSP's leveraged authorization.
- **Hybrid / shared: about 60–90 more (roughly 20–30%).** AC-2, AC-3, AC-6, IA-2/IA-5, AU-2/3/6/11, CM-2/3/6/7, SC-7, SI-2, SI-4, CP-9, IR-4… The platform supplies the mechanism and evidence; the program supplies decisions, reviews and app-level enforcement.
- **Never from the platform:** the `-1` policy/procedure controls, AT, PS, PL, PM, most CA/RA process controls, IR process, and the program's application-layer controls (SI-10, SC-28 of app data, app authorization logic). These come from the DoD Component's organizational CCPs or from the program.

So the thesis holds in a narrower form. The platform can credibly take roughly a third of the technical burden, as provided or hybrid, with live evidence. That is a strong value proposition for cATO. The claim that "every program inherits" what the engine marks implemented and inherited is not credible.

---

## Things done right (keep them)
- Raw evidence JSON, `checkedAt`, and 100-run history per assertion, embedded as SSP back-matter.
- Conservative STIG `Not_Reviewed` defaults, honest per-rule notes, verbatim XCCDF text, CCIs and Rule IDs.
- POA&M risk columns left blank for the ISSO. Single-scanner findings are flagged.
- Read-only RBAC, and GET-only Keycloak access with a least-privilege role recommendation.
- REPORTS.md "Read this first" and the Caveats section. CONTROLS.md "Limitations" (the API audit `unknown` on MicroK8s is exactly right).
- Deterministic UUIDs, so artifacts can be regenerated identically per scan.

## Key file references
- Status derivation: `api/src/posture/controls_engine/engine.py:151-220` (inherited 209-210, NA 203-205, implemented 192-193)
- OSCAL state map: `api/src/posture/controls_engine/ssp.py:43`; inheritance props at 199-200 and 214-217; placeholders at 255-269
- NIST tagging: `api/src/posture/reports/data/controls.yaml:27-55`, `api/src/posture/reports/_common.py:27-44`
- ODP defaults: `api/src/posture/controls_engine/settings.py:17-26`
- SLA clock: `api/src/posture/worker.py:568-583`; `api/src/posture/reports/_common.py:20`
- POA&M: `api/src/posture/reports/poam.py:31-41` (columns), 232 (single control), 240 (mitigations)
- STIG evaluation: `api/src/posture/reports/stig.py:75-152`; mapping `api/src/posture/reports/data/stig_mapping.yaml` (V-242383 @248, V-233127 @3473, V-233163 @3509, V-233233 @3578, V-233234 @3619)
- AR findings: `api/src/posture/reports/oscal.py:224-239`
- Unsafe passes:
  - `assertions/certmanager.py:30-45`
  - `assertions/observability.py:114-156`
  - `assertions/registry.py:301-329`
  - `assertions/keycloak.py:79-108`
  - `assertions/kubernetes.py:93-95`
