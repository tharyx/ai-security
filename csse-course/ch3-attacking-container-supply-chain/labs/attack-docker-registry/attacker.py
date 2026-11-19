"""What an attacker (or a pentester on an authorised test) does against an open registry.

All calls go to the in-process Registry object. Nothing leaves the process. The "poisoned" image only adds a layer
with a canary marker, like the backdoor lab.
"""
from __future__ import annotations

import re

SECRET_RX = re.compile(r"(TOKEN|SECRET|PASSWORD|API_?KEY)=", re.I)


def enumerate_registry(reg, headers=None, scheme="http") -> dict:
    """Catalog, then tags, then manifests; collect anything that looks like a baked-in secret."""
    cat = reg.handle("GET", "/v2/_catalog", headers=headers, scheme=scheme)
    result: dict = {"status": cat.status, "repos": {}, "secrets": []}
    if cat.status != 200:
        return result
    for repo in cat.body["repositories"]:
        tags = reg.handle("GET", f"/v2/{repo}/tags/list", headers=headers, scheme=scheme).body.get("tags", [])
        result["repos"][repo] = tags
        for tag in tags:
            m = reg.handle("GET", f"/v2/{repo}/manifests/{tag}", headers=headers, scheme=scheme)
            for env in (m.body or {}).get("config", {}).get("Env", []):
                if SECRET_RX.search(env):
                    result["secrets"].append((f"{repo}:{tag}", env.split("=")[0]))
    return result


def poison_tag(reg, repo: str, tag: str, headers=None, scheme="http"):
    """Overwrite an existing tag with a manifest that has one extra (canary) layer."""
    from_reg = reg.handle("GET", f"/v2/{repo}/manifests/{tag}", headers=headers, scheme=scheme)
    if from_reg.status != 200:
        return from_reg
    evil = {**from_reg.body, "layers": from_reg.body["layers"] + [{"digest": "sha256:" + "c" * 64, "size": 1, "annotations": {"note": "CANARY-BACKDOOR"}}]}
    return reg.handle("PUT", f"/v2/{repo}/manifests/{tag}", headers=headers, body=evil, scheme=scheme)
