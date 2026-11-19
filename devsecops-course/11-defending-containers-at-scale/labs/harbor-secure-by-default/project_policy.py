"""Check a Harbor-style project policy (JSON fixture) and decide whether a pull is allowed.

Mirrors the Harbor project settings concept: private project, auto-scan on push,
'prevent vulnerable images from running' at a severity, signature required, RBAC roles
for members, robot accounts with limited scope. Field names are this lab's own: map to
the real Harbor API/UI in the csse ch6 lab and the Harbor docs (verify at source).
"""
from __future__ import annotations

SEV = ["none", "low", "medium", "high", "critical"]


def audit_project(p: dict) -> list[str]:
    out = []
    if p.get("public"):
        out.append("project is public: anyone can pull")
    if not p.get("auto_scan"):
        out.append("auto-scan on push is off")
    if p.get("prevent_vulnerable_severity", "none") in ("none",):
        out.append("no 'prevent vulnerable images from running' threshold")
    elif SEV.index(p["prevent_vulnerable_severity"]) > SEV.index("high"):
        out.append("prevent threshold is critical only: HIGH images can still be pulled")
    if not p.get("require_signature"):
        out.append("signature (cosign/Notation) not required to pull")
    for m in p.get("members", []):
        if m["role"] == "project_admin" and not m.get("approved"):
            out.append(f"member {m['name']} is project_admin without approval")
    for r in p.get("robots", []):
        if "delete" in r.get("permissions", []) or r.get("expires_days", 0) in (0, None) or r["expires_days"] > 90:
            out.append(f"robot {r['name']} is over-privileged or long-lived")
    return out


def may_pull(p: dict, image: dict) -> tuple[bool, str]:
    """image = {max_severity, signed, scanned}."""
    thr = p.get("prevent_vulnerable_severity", "none")
    if p.get("require_signature") and not image.get("signed"):
        return False, "unsigned image"
    if thr != "none":
        if not image.get("scanned"):
            return False, "image has not been scanned"
        if SEV.index(image["max_severity"]) >= SEV.index(thr):
            return False, f"has {image['max_severity']} vulnerabilities (threshold {thr})"
    return True, "allowed"
