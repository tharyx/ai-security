"""Offline auditor for S3 / Azure Blob / GCS / CDN / DNS fixtures. Reads JSON only; no cloud calls."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    resource: str
    detail: str


def _as_list(x):
    return x if isinstance(x, list) else [x]


def _public_principal(p) -> bool:
    if p == "*":
        return True
    return isinstance(p, dict) and "*" in _as_list(p.get("AWS", []))


def _actions(stmt):
    return [a.lower() for a in _as_list(stmt.get("Action", []))]


def audit_s3(buckets):
    out = []
    for b in buckets:
        name = b["name"]
        bpa = b.get("block_public_access", False)
        for st in b.get("policy", {}).get("Statement", []):
            if st.get("Effect") != "Allow" or not _public_principal(st.get("Principal")) or st.get("Condition"):
                continue
            acts = _actions(st)
            if bpa:
                continue
            if any(a in ("s3:*", "*") or a.startswith("s3:put") or a.startswith("s3:delete") for a in acts):
                out.append(Finding("S3-PUBLIC-WRITE", "critical", name, "anonymous principals may write or delete objects"))
            if any(a in ("s3:*", "*", "s3:getobject", "s3:listbucket") for a in acts):
                out.append(Finding("S3-PUBLIC-READ", "high", name, "anonymous principals may read objects"))
        if any(a.startswith("AllUsers") for a in b.get("acl", [])):
            out.append(Finding("S3-ACL-ALLUSERS", "high", name, "legacy ACL grants the AllUsers group"))
        if b.get("website") and not bpa:
            out.append(Finding("S3-WEBSITE-HTTP", "medium", name, "website endpoint is public and HTTP-only; front it with a CDN using HTTPS"))
        if not bpa:
            out.append(Finding("S3-NO-BLOCK-PUBLIC-ACCESS", "medium", name, "account/bucket Block Public Access is off"))
        if not b.get("encryption", True):
            out.append(Finding("S3-NO-ENCRYPTION", "low", name, "default encryption not set"))
        if not b.get("versioning", True):
            out.append(Finding("S3-NO-VERSIONING", "low", name, "no versioning: overwritten objects cannot be recovered"))
    return out


def audit_azure(accounts):
    out = []
    for a in accounts:
        name = a["account"]
        for c in a.get("containers", []):
            if a.get("allow_blob_public_access") and c.get("public_access", "none") != "none":
                sev = "high" if c["public_access"] == "container" else "medium"
                out.append(Finding("AZ-BLOB-PUBLIC", sev, f"{name}/{c['name']}", f"anonymous access level '{c['public_access']}'"))
        if not a.get("https_only", True):
            out.append(Finding("AZ-HTTP-ALLOWED", "medium", name, "secure transfer (HTTPS only) is off"))
        if a.get("shared_key_enabled", False):
            out.append(Finding("AZ-SHARED-KEY", "medium", name, "shared key access enabled; prefer Entra ID authorization"))
        for s in a.get("sas", []):
            if s.get("expiry_days", 0) > 7:
                out.append(Finding("AZ-SAS-LONG-LIVED", "high", f"{name}/{s['name']}", f"SAS valid {s['expiry_days']} days with '{s['permissions']}'"))
    return out


def audit_gcs(buckets):
    out = []
    for b in buckets:
        name = b["name"]
        for binding in b.get("iam", []):
            pub = [m for m in binding["members"] if m in ("allUsers", "allAuthenticatedUsers")]
            if pub:
                writes = any(k in binding["role"].lower() for k in ("creator", "admin", "writer"))
                out.append(Finding("GCS-PUBLIC-WRITE" if writes else "GCS-PUBLIC-READ", "critical" if writes else "high",
                                   name, f"{binding['role']} granted to {','.join(pub)}"))
        if b.get("public_access_prevention") != "enforced":
            out.append(Finding("GCS-NO-PAP", "low", name, "public access prevention is not enforced"))
        if not b.get("uniform_access", False):
            out.append(Finding("GCS-FINE-GRAINED-ACL", "low", name, "uniform bucket-level access is off (object ACLs possible)"))
    return out


def audit_cdn(distributions, s3_buckets, existing_buckets):
    out = []
    pub = {b["name"] for b in s3_buckets if not b.get("block_public_access")}
    for d in distributions:
        if d["origin"] not in existing_buckets:
            out.append(Finding("CDN-ORIGIN-MISSING", "critical", d["name"],
                               f"origin '{d['origin']}' does not exist: anyone could register that name and serve content"))
            continue
        if d["origin_type"] == "s3" and not d.get("origin_access_control"):
            sev = "high" if d["origin"] in pub else "medium"
            out.append(Finding("CDN-NO-OAC", sev, d["name"], "bucket origin is reachable without Origin Access Control/Identity (CDN can be bypassed)"))
        if d["origin_type"] == "s3_website":
            out.append(Finding("CDN-WEBSITE-ORIGIN", "medium", d["name"], "website endpoint origin must stay public and cannot use OAC"))
    return out


def audit_dns(records, existing_targets):
    out = []
    ours = set(existing_targets)
    for r in records:
        if r["type"] == "CNAME" and r["target"] not in ours:
            out.append(Finding("DNS-DANGLING", "high", r["name"], f"CNAME -> {r['target']} is not backed by a resource you own (takeover risk)"))
    return out


def audit(estate: dict):
    f = []
    f += audit_s3(estate.get("s3", []))
    f += audit_azure(estate.get("azure_blob", []))
    f += audit_gcs(estate.get("gcs", []))
    f += audit_cdn(estate.get("cdn", []), estate.get("s3", []), estate.get("existing_buckets", []))
    f += audit_dns(estate.get("dns", []), estate.get("existing_targets", []))
    return sorted(f, key=lambda x: (SEV_ORDER[x.severity], x.resource, x.rule))


def load(path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
