"""cert-manager assertions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from ..context import EngineContext
from ..model import Result, assertion, failed, not_applicable, passed

C = "cert-manager"
CLUSTER_ISSUERS = "/apis/cert-manager.io/v1/clusterissuers"
CERTIFICATES = "/apis/cert-manager.io/v1/certificates"


def _ready(obj: dict[str, Any]) -> bool:
    return any(c.get("type") == "Ready" and c.get("status") == "True"
               for c in (obj.get("status") or {}).get("conditions") or [])


def _ts(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


@assertion(id="cm-issuer-ready", title="A cert-manager ClusterIssuer exists and is Ready", controls=["SC-12", "SC-17", "IA-5(2)"],
           objectives=["sc-12_obj-1", "sc-17_obj.a", "ia-5.2_obj.b.1"],
           component=C, severity="high")
async def issuer_ready(ctx: EngineContext) -> Result:
    """At least one ClusterIssuer exists, every ClusterIssuer reports Ready, and every ClusterIssuer
    is on the approved-CA allowlist (`controlsEngine.approvedIssuers`): issuers that chain to DoD PKI,
    an ECA or the organization's approved CA. A `selfSigned` issuer is never approved by default,
    and an empty allowlist fails (SC-17 needs an approved CA; compliance review M4/M5)."""
    issuers = await ctx.k8s_list_optional(CLUSTER_ISSUERS)
    if issuers is None:
        return failed("cert-manager is not installed (no ClusterIssuer API)")
    rows = [{"name": i["metadata"]["name"], "ready": _ready(i),
             "kind": next((k for k in ("ca", "acme", "vault", "selfSigned", "venafi") if k in (i.get("spec") or {})),
                          "other")} for i in issuers]
    approved = list(ctx.config.approved_issuers)
    for r in rows:
        r["approved"] = r["name"] in approved
    ev = {"issuers": rows, "approvedIssuers": approved}
    if not rows:
        return failed("no ClusterIssuer is configured", **ev)
    bad = [r["name"] for r in rows if not r["ready"]]
    if bad:
        return failed(f"ClusterIssuer(s) not Ready: {', '.join(bad)}", **ev)
    if not approved:
        return failed("no approved-CA allowlist configured (controlsEngine.approvedIssuers); issuers present: "
                      + ", ".join(f"{r['name']} ({r['kind']})" for r in rows), **ev)
    unapproved = [r for r in rows if not r["approved"]]
    if unapproved:
        return failed("ClusterIssuer(s) not on the approved-CA allowlist: "
                      + ", ".join(f"{r['name']} ({r['kind']})" for r in unapproved), **ev)
    return passed(f"{len(rows)} approved ClusterIssuer(s) Ready: "
                  + ", ".join(f"{r['name']} ({r['kind']})" for r in rows), **ev)


@assertion(id="cm-certificates-valid", title="Certificates are Ready and not near expiry",
           controls=["SC-12", "SC-17"],
           objectives=["sc-12_obj-2", "sc-17_obj.a"], component=C, severity="high")
async def certificates_valid(ctx: EngineContext) -> Result:
    """Every cert-manager Certificate is Ready, unexpired, and not inside the renewal window
    (`controlsEngine.certRenewalWindowDays`) without having been renewed."""
    certs = await ctx.k8s_list_optional(CERTIFICATES)
    if certs is None:
        return failed("cert-manager is not installed (no Certificate API)")
    if not certs:
        return not_applicable("no Certificate resources")
    now = datetime.now(UTC)
    window = timedelta(days=ctx.config.cert_renewal_window_days)
    rows, bad = [], []
    for c in certs:
        st = c.get("status") or {}
        na = _ts(st.get("notAfter"))
        row = {"certificate": f"{c['metadata']['namespace']}/{c['metadata']['name']}", "ready": _ready(c),
               "notAfter": st.get("notAfter"), "renewalTime": st.get("renewalTime"),
               "issuer": ((c.get("spec") or {}).get("issuerRef") or {}).get("name")}
        if not row["ready"]:
            row["problem"] = "not Ready"
        elif na is None:
            row["problem"] = "no notAfter in status"
        elif na <= now:
            row["problem"] = "expired"
        elif na - now < window:
            row["problem"] = f"expires in {(na - now).days} day(s)"
        rows.append(row)
        if "problem" in row:
            bad.append(row)
    if bad:
        return failed(f"{len(bad)} of {len(rows)} certificate(s) unhealthy: "
                      + ", ".join(f"{b['certificate']} ({b['problem']})" for b in bad[:10]), certificates=rows)
    soonest = min((r["notAfter"] for r in rows if r["notAfter"]), default=None)
    return passed(f"{len(rows)} certificate(s) Ready; earliest expiry {soonest}", certificates=rows)
