# Architecture: from container scans to an 800-53 control picture

This page is the 30,000-foot view of how the pack turns what Nebari deploys into
continuous ATO evidence. It is written for people deciding whether to adopt the
model, not for people operating it. Operating docs: [CONTROLS.md](CONTROLS.md),
[REPORTS.md](REPORTS.md), [PROVENANCE.md](PROVENANCE.md), [SCORING.md](SCORING.md).

## 1. The core idea: ownership beats scanning

A vulnerability scanner looks at an artifact and can only report defects. It can
say "RA-5: here are CVEs". It can never say "AC-2 is satisfied", because it does
not own identity.

Nebari Infrastructure Core (NIC) deploys the whole platform declaratively:
Keycloak, Envoy Gateway, cert-manager, logging, the nebari-operator, and every
software pack. So for a large set of controls the platform knows two things no
scanner can:

1. **What the intended implementation is**, because NIC wrote it.
2. **Whether it is actually in effect right now**, because the pack can query it.

Put those together and the platform becomes what SP 800-53 calls a **common
control provider**. The platform implements a control once, continuously proves
it, and every program running on Nebari inherits it.

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
    SAST -->|"RA-5, SI-2, SA-11"| C
    IMG -->|"RA-5, SI-2, CM-14, SR-4"| C
    K8S -->|"AC-6, CM-6, CM-7, SC-7"| C
    IDP -->|"AC-2, AC-7, IA-2, IA-5, AC-12"| C
    EDGE -->|"AC-3, SC-8, SC-12, SC-17, SC-23"| C
    AUD -->|"AU-2, AU-4, AU-6, AU-12, SI-4"| C
    OPS -->|"CM-3, CM-8, CA-5, CA-7, RA-5(2)"| C
    C(["NIST SP 800-53 rev5<br/>control statuses with evidence"])
```

## 2. Three evidence layers, one control picture

The pack collects evidence at three altitudes. Each layer answers different
control families; together they cover most of the technical controls in the
MODERATE baseline.

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
        ASRT["35 live assertions<br/>queried from the running cluster<br/>pass / fail / unknown + raw evidence"]
        COMP --> ASRT
    end
    CONS & PROV -->|"RA-5, SI-2, CM-14, SR-3, SR-4"| STATUS
    STIG -->|"AC-6, CM-6, CM-7, SC-7, SC-6, SI-13"| STATUS
    ASRT -->|"AC, AU, IA, SC, CA, CM, SI, SR families"| STATUS
    STATUS(["Per-control status<br/>implemented · partial · not implemented ·<br/>inherited · unknown · not applicable"])
    STATUS --> SCORE["Posture score & grade<br/>0.6 vulnerability · 0.25 configuration · 0.15 supply chain"]
```

## 3. Control inheritance: the platform as common control provider

This is the part that changes the economics of an ATO. A program's SSP must
answer every control. Most of the technical answers describe the platform the
program runs on. With this model the program inherits those from a platform
SSP that is machine-generated and refreshed on every scan, and writes only the
controls that are genuinely its own.

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
    subgraph common["Platform SSP: common controls (implemented once, proven continuously)"]
        AC["AC-2 AC-3 AC-6 AC-7 AC-12 AC-14"]
        IA["IA-2 IA-2(1) IA-5 IA-5(1)"]
        SC["SC-7 SC-8 SC-12 SC-13 SC-17 SC-23"]
        AU["AU-2 AU-4 AU-6 AU-11 AU-12"]
        CMF["CM-6 CM-7 CM-8 CM-14"]
        RA["RA-5 RA-5(2) CA-5 CA-7 SI-2 SI-4 SR-4"]
    end
    subgraph program["Program SSP (e.g. a research program seeking ATO)"]
        INH["Inherited from platform<br/>→ reference platform SSP + live evidence"]
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
  *inherited from the organization*. That is a claim the ISSO must stand behind,
  not evidence. `controlsEngine.inheritOrganizationalControls=false` reports
  them as *not implemented* instead.
- **Some technical controls are invisible from inside the cluster.** API-server
  audit logging on MicroK8s returns *unknown* for exactly that reason. More is
  visible on NIC-provisioned cloud clusters, but never everything.
- **Organization-defined parameters** (lockout threshold, idle timeout, password
  length, log retention) default to FedRAMP Moderate values and are settings,
  because an IL4 program may tailor differently.
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
        SAR["Security Assessment Report<br/>pdf / html"]
        OAR["OSCAL assessment-results"]
        OSSP["OSCAL system-security-plan +<br/>component-definition"]
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
    V["Next scan verifies<br/>status returns to implemented"]
    R["Artifacts regenerated<br/>SSP · AR · POA&M · STIG · SAR"]
    S --> E --> D
    D -->|"yes"| P --> F --> V --> S
    D -->|"no"| R --> S
```

## 6. What this looked like on the first run

The `grace` lab cluster, MODERATE baseline, 2026-10-03 (details in
[CONTROLS.md](CONTROLS.md)): 35 assertions, 19 pass, 15 fail, 1 unknown. The
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
