# Decisions log

- 2026-10-02: No ArgoCD on grace. Inventory source is the Kubernetes API (pods, owners,
  NebariApps), not ArgoCD. This also works on NIC clusters that do run ArgoCD.
- 2026-10-02: Admin gate = NebariApp `auth.groups` (grace operator enforces at gateway)
  + optional chart-rendered SecurityPolicy for upstream operators + API-side JWT/group
  verification. Default admin group `admin` (exists in grace's realm).
- 2026-10-02: Monorepo (chart + api + ui) for the experiment. Nebari convention is code in
  separate repos; split later if promoted.
- 2026-10-02: Mirror-then-scan via skopeo into the in-cluster registry so all three
  scanners see identical bytes and Docker Hub is pulled once per digest.
