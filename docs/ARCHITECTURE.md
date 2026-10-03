# Architecture: from container scans to an 800-53 control picture

This page is the 30,000-foot view of how the pack turns what Nebari deploys into
continuous ATO evidence. It is written for people deciding whether to adopt the
model, not for people operating it. Operating docs: [CONTROLS.md](CONTROLS.md),
[REPORTS.md](REPORTS.md), [PROVENANCE.md](PROVENANCE.md), [SCORING.md](SCORING.md).

## 1. The core idea: ownership beats scanning

A vulnerability scanner looks at an artifact and can only report defects. It can
say "SI-2: here are CVEs". It cannot see how identity, the gateway or logging are
configured, because it does not own them. (No tool says a control is satisfied;
an assessor does.)

Nebari Infrastructure Core (NIC) deploys the whole platform declaratively:
Keycloak, Envoy Gateway, cert-manager, logging, the nebari-operator, and every
software pack. So for a large set of controls the platform knows two things no
scanner can:

1. **What the intended implementation is**, because NIC wrote it.
2. **Whether it is actually in effect right now**, because the pack can query it.

Put those together and the platform can serve as an **evidence source for a
common control provider**. Inheritance itself requires more than evidence: the
platform's controls must be assessed and authorized (its own SSP, SAR and ATO,
for example as a common control provider in eMASS) and documented in a Customer
Responsibility Matrix (CRM) that says, per control, what is provided, what is
shared and what stays with each program. The pack produces the evidence and a
draft CRM (`GET /compliance/crm`, report `crm`); it does not make anything
inheritable on its own.

```mermaid
flowchart LR
    subgraph tools["Where existing tools live"]
        direction TB
        SAST["Static code scanners<br/>(SAST, dependency audit)"]
        IMG["Container scanners<br/>(Trivy, Grype, Clair)"]
    end
    subgraph platform["What only the platform can see"]
        direction TB
        K8S["Workload configuration<br/>privileged, root, hostPath,<br/>NetworkPolicy, PodSecurity"]
        IDP["Identity & access<br/>Keycloak realm policy, MFA,<br/>lockout, session timeouts"]
        EDGE["Boundary & crypto<br/>gateway TLS, HTTP redirect,<br/>SecurityPolicy per app, cert-manager"]
        AUD["Audit & monitoring<br/>Loki ingest, retention,<br/>Prometheus, Alertmanager receivers"]
        OPS["Platform operations<br/>operator-reconciled apps,<br/>registry access, scan freshness"]
    end
    SAST -->|"SI-2, SA-11"| C
    IMG -->|"SI-2, SA-22, SR-4"| C
    K8S -->|"AC-6, CM-6, CM-7, SC-7, SC-39"| C
    IDP -->|"AC-7, AC-12, IA-2(1), IA-5(1), SC-10"| C
    EDGE -->|"AC-3, SC-8, SC-12, SC-17, SC-23"| C
    AUD -->|"AU-4, AU-5, AU-11, AU-12, SI-4(5)"| C
    OPS -->|"CM-8, RA-5, RA-5(2), CA-5 (partial)"| C
    C(["NIST SP 800-53 rev5<br/>evidence status per control and<br/>SP 800-53A objective"])
```

## 2. Three evidence layers, one control picture

The pack collects evidence at three altitudes. Each layer answers different
control families; together they contribute automated evidence to about 52 of the
287 MODERATE controls (39 assertions plus scan and posture results). Most of those
are partial or hybrid: the platform evidences some SP 800-53A objectives and the
program owns the rest.

```mermaid
flowchart TB
    subgraph L1["Layer 1: Image (what is in the container)"]
        direction LR
        INV["Inventory<br/>every running pod → unique image by digest"]
        MIR["Mirror once<br/>skopeo → in-cluster registry"]
        T["Trivy"]
        G["Grype"]
        CL["Clair"]
        CONS["Consensus<br/>per CVE + package,<br/>agreement 1/3 · 2/3 · 3/3"]
        PROV["Provenance<br/>cosign signature, SLSA attestation,<br/>SBOM, update available"]
        INV --> MIR --> T & G & CL --> CONS
        INV --> PROV
    end
    subgraph L2["Layer 2: Workload (how the container is run)"]
        direction LR
        CHK["16 posture checks<br/>privileged · run-as-root · capabilities ·<br/>host namespaces · hostPath · seccomp ·<br/>limits · probes · mutable tag · SA token · NetworkPolicy"]
        STIG["STIG mapping<br/>Kubernetes STIG V2R6 · Container Platform SRG V2R4"]
        CHK --> STIG
    end
    subgraph L3["Layer 3: Platform (what NIC deployed and whether it is in effect)"]
        direction LR
        COMP["Component definitions<br/>Keycloak · Envoy Gateway · cert-manager ·<br/>nebari-operator · Loki · Prometheus ·<br/>Kubernetes · registry · this pack"]
        ASRT["39 live assertions<br/>queried from the running cluster<br/>pass / fail / unknown + raw evidence"]
        COMP --> ASRT
    end
    CONS & PROV -->|"SI-2, SR-4, CM-14 (signatures)"| STATUS
    STIG -->|"AC-6, CM-6, CM-7, SC-5, SC-7, SC-39"| STATUS
    ASRT -->|"AC, AU, IA, SC, CA, CM, SA, SI families"| STATUS
    STATUS(["Evidence status per control<br/>passing · partial · failing · hybrid ·<br/>not assessed · org-provided (unverified) ·<br/>inherited (named provider) · not applicable (tailored)"])
    STATUS --> SCORE["Hygiene index (A-F trend, not an assessment result)<br/>0.6 vulnerability · 0.25 configuration · 0.15 supply chain"]
```

## 3. Control inheritance: what it takes

This is the part that can change the economics of an ATO, and the part most
easily overstated. A program's SSP must answer every control. Many technical
answers describe the platform the program runs on. A program can *inherit* them
only from a platform that has been assessed and authorized as a common control
provider, with a CRM; a machine-generated SSP refreshed every scan does not
substitute for that (the AO authorizes a state plus a ConMon strategy, not a
live feed). What the pack gives that model: continuous evidence for the
platform-provided and hybrid controls, and a draft CRM. A realistic ceiling at
MODERATE is roughly 15-30 controls fully provided by a platform like this and
60-90 hybrid; policy, personnel and most process controls never come from the
platform.

```mermaid
flowchart TB
    subgraph nic["Nebari Infrastructure Core (deploys declaratively)"]
        KC["Keycloak"]
        EG["Envoy Gateway +<br/>operator SecurityPolicy"]
        CM["cert-manager"]
        OP["nebari-operator"]
        LG["Loki / Promtail"]
        PM["Prometheus /<br/>Alertmanager"]
        K8["Kubernetes<br/>PodSecurity · RBAC · NetworkPolicy"]
        RG["Container registry"]
        SP["security-posture pack"]
    end
    subgraph common["Platform evidence (provided or hybrid once the platform is authorized; CRM)"]
        AC["Provided: AC-7 AC-12 SC-23 · hybrid: AC-2 AC-3 AC-6 AC-14"]
        IA["Hybrid: IA-2 IA-2(1) IA-2(2) IA-2(12) IA-5(1) IA-5(2)"]
        SC["Hybrid: SC-7 SC-7(5) SC-8 SC-8(1) SC-10 SC-12 SC-17"]
        AU["Hybrid: AU-4 AU-5 AU-11 AU-12"]
        CMF["Hybrid: CM-5 CM-6 CM-7 CM-8"]
        RA["Provided: RA-5(2) · hybrid: RA-5 SA-22 SI-2 SI-4(5) CA-5"]
    end
    subgraph program["Program SSP (e.g. a research program seeking ATO)"]
        INH["Inherited / hybrid from the authorized platform<br/>→ leveraged authorization + CRM + live evidence"]
        OWN["Program-specific controls<br/>app authorization logic, data handling,<br/>program policies and procedures"]
        ORG["Organization-level controls<br/>policy, training, personnel, contingency<br/>(not provable by any platform)"]
    end
    KC --> AC & IA
    EG --> AC & SC
    CM --> SC
    OP --> CMF
    LG & PM --> AU
    K8 --> AC & CMF & SC
    RG --> CMF
    SP --> RA
    common --> INH
    INH --> SSP
    OWN --> SSP
    ORG --> SSP
    SSP(["Program System Security Plan<br/>submitted to the AO"])
```

Honest boundaries of the model:

- **Organizational controls** (roughly two thirds of the catalog) are policies,
  training, personnel and contingency planning. The engine reports them as
  *not assessed*, or, with `controlsEngine.inheritOrganizationalControls=true`,
  as *organization-provided (unverified)*, which never counts as implemented.
  A control is *inherited* only when a named, authorized common control
  provider is configured for it (`controlsEngine.commonControlProviders`).
- **Some technical controls are invisible from inside the cluster.** API-server
  audit logging on MicroK8s returns *unknown* for exactly that reason. More is
  visible on NIC-provisioned cloud clusters, but never everything.
- **Organization-defined parameters** (lockout threshold, idle timeout, password
  length, log retention) come from the selected profile's cited ODP set (FedRAMP
  Rev5, or DISA SRG / CNSSI 1253 for the DoD approximation) and can be
  overridden in settings. Only the NIST LOW / MODERATE / HIGH and FedRAMP Rev5
  Moderate control lists are exact; DoD programs need their CNSSI 1253 control
  set from eMASS.
- **Assessors accept evidence, not tools.** Every assertion carries its raw
  evidence and timestamp so a human doing a sample-based check can verify it.

## 4. The evidence pipeline: from live cluster to eMASS

```mermaid
flowchart LR
    subgraph sources["Live sources (queried every scan)"]
        A1["Kubernetes API"]
        A2["Keycloak admin API"]
        A3["Gateway, cert-manager CRs"]
        A4["Loki, Prometheus, Alertmanager"]
        A5["Registries<br/>(layers, signatures, tags)"]
    end
    subgraph engine["Evidence engine (worker)"]
        SCAN["Image scan<br/>trivy · grype · clair"]
        POST["Posture checks"]
        PROVE["Provenance checks"]
        ASR["Control assertions"]
        DERIVE["Status derivation<br/>catalog (rev5) + baseline profile +<br/>component definitions + assertion results"]
    end
    subgraph store["Postgres (history of every scan)"]
        DB[("findings · posture results ·<br/>provenance · assertion results ·<br/>control statuses · snapshots")]
    end
    subgraph out["Generated artifacts"]
        POAM["POA&M<br/>eMASS import xlsx / csv"]
        CKL["STIG checklist<br/>.ckl / .cklb (STIG Viewer)"]
        SAR["Automated assessment summary<br/>(input to the SAR) pdf / html"]
        OAR["OSCAL assessment-results"]
        OSSP["OSCAL SSP draft + component-definition<br/>+ draft CRM"]
        VEX["Inventory · vuln export ·<br/>CycloneDX VEX"]
        GRAF["provenance-collector compatible<br/>/api/reports/latest for Grafana"]
    end
    subgraph consumers["Consumers"]
        EMASS["eMASS"]
        SV["STIG Viewer / STIG Manager"]
        AO["ISSO · ISSM · AO"]
        UI["Admin UI<br/>(Nebari design system)"]
        GF["Grafana"]
    end
    A1 --> SCAN & POST & ASR
    A2 & A3 & A4 --> ASR
    A5 --> SCAN & PROVE
    SCAN & POST & PROVE & ASR --> DERIVE --> DB
    DB --> POAM & CKL & SAR & OAR & OSSP & VEX & GRAF & UI
    POAM --> EMASS
    CKL --> SV
    SAR & OAR & OSSP --> AO
    GRAF --> GF
```

## 5. The continuous-ATO loop

Once the evidence is live, the ATO stops being a document and becomes a loop.
Every scan re-derives control status; anything that regresses shows up as drift
with an SLA clock, and most platform-level fixes are one-line NIC configuration
changes that the next scan verifies.

```mermaid
flowchart LR
    S["Scheduled scan<br/>(default every 6 h, or on demand)"]
    E["Evidence refreshed<br/>images · workloads · platform assertions"]
    D{"Drift or new finding?"}
    P["POA&M row created<br/>control, source, first seen,<br/>SLA due date (15/30/90/180 d)"]
    F["Fix at the source<br/>NIC config · chart values ·<br/>image update · Keycloak policy"]
    V["Next scan verifies<br/>evidence returns to passing"]
    R["Artifacts regenerated<br/>SSP · AR · POA&M · STIG · SAR"]
    S --> E --> D
    D -->|"yes"| P --> F --> V --> S
    D -->|"no"| R --> S
```

## 6. What this looked like on the first run

The `grace` lab cluster, MODERATE baseline, 2026-10-03 (details in
[CONTROLS.md](CONTROLS.md)): 35 assertions (now 39), 19 pass, 15 fail, 1 unknown. The
platform reported on itself: no Keycloak password policy, no MFA on the admin
account, login and admin events not recorded, 21 of 23 namespaces without a
PodSecurity enforce label, no default-deny NetworkPolicy in any app namespace,
anonymous access to the in-cluster registry. Nobody wrote those findings down.

Most of them are one-line changes in NIC. That points at the next step: ship a
hardened baseline in the operator so a fresh Nebari deployment starts mostly
green, and this pack becomes the drift detector rather than the bearer of bad
news.

## Where the pieces live

| Concern | Code | Doc |
|---|---|---|
| Inventory, mirroring, scanners, consensus, scoring | `api/src/posture/{inventory,mirror,scanners,correlate,scoring}.py` | [SCORING.md](SCORING.md) |
| Posture checks and STIG mapping | `api/src/posture/posture_checks.py`, `reports/data/stig_mapping.yaml` | [REPORTS.md](REPORTS.md) |
| Provenance (signatures, SLSA, SBOM, updates, Helm) | `api/src/posture/provenance/` | [PROVENANCE.md](PROVENANCE.md) |
| Catalog, component definitions, assertions, SSP | `api/src/posture/controls_engine/` | [CONTROLS.md](CONTROLS.md) |
| NIST control tagging | `api/src/posture/reports/data/controls.yaml` | [DESIGN.md §11](DESIGN.md) |
| Report generators | `api/src/posture/reports/` | [REPORTS.md](REPORTS.md) |
| Chart, admin gate, RBAC | `chart/` | [README](../README.md) |
