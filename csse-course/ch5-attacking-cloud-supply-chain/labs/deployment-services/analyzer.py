"""Analyze CI/CD deployment-service fixtures and simulate artifact-bucket tampering. Offline."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ADMIN = ("*", "*:*", "administratoraccess", "roles/owner", "roles/editor", "owner", "contributor")
SECRET_NAME = re.compile(r"(secret|token|password|key)", re.I)


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    pipeline: str
    detail: str


def analyze(doc):
    out = []
    pipelines = doc["pipelines"]
    internal = set(doc["pipeline_principals"])
    role_use = {}
    for p in pipelines:
        role_use.setdefault(p["service_role"]["name"], []).append(p["name"])
    for p in pipelines:
        n, role, store = p["name"], p["service_role"], p["artifact_store"]
        acts = [a.lower() for pol in role["policies"] for a in pol["Action"]]
        if any(a in ADMIN for a in acts):
            out.append(Finding("ROLE-OVERPRIVILEGED", "critical", n, f"{p['service']} role '{role['name']}' has admin-like permissions"))
        if len(role_use[role["name"]]) > 1:
            out.append(Finding("ROLE-SHARED", "medium", n, f"role '{role['name']}' shared by {', '.join(role_use[role['name']])}"))
        if p.get("service_connection_authorized_for_all_pipelines"):
            out.append(Finding("CONNECTION-OPEN-TO-ALL", "high", n, "service connection usable by every pipeline in the project"))
        outsiders = [w for w in store["writers"] if w not in internal]
        if outsiders:
            out.append(Finding("ARTIFACT-STORE-WRITABLE", "critical", n, f"non-pipeline principals can write artifacts: {', '.join(outsiders)}"))
        if not store.get("digest_verification"):
            out.append(Finding("ARTIFACT-NO-DIGEST-CHECK", "high", n, "deploy stage does not verify the artifact digest from the build stage"))
        if not store.get("versioning"):
            out.append(Finding("ARTIFACT-NO-VERSIONING", "low", n, "no object versioning: tampering leaves no previous copy"))
        if not p.get("approval_before_prod"):
            out.append(Finding("NO-PROD-APPROVAL", "medium", n, "no manual approval before the production stage"))
        for k in p.get("plain_variables", {}):
            if SECRET_NAME.search(k):
                out.append(Finding("PLAIN-SECRET-VARIABLE", "high", n, f"{k} is a plain pipeline variable; use a secret store"))
    return sorted(out, key=lambda f: (SEV[f.severity], f.pipeline, f.rule))


class ArtifactStore:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, principal, key, data, writers):
        if principal not in writers:
            raise PermissionError(f"{principal} may not write {key}")
        self.objects[key] = data


def run_pipeline(pipeline, attacker=None, tamper_payload=b"CANARY-malicious-build"):
    """Build -> (attacker swaps artifact if allowed) -> deploy. Returns what was deployed."""
    store = ArtifactStore()
    writers = pipeline["artifact_store"]["writers"]
    build = b"legit-build-v1"
    digest = hashlib.sha256(build).hexdigest()  # recorded in the pipeline execution, not in the bucket
    store.put(writers[0], "app.zip", build, writers)
    tampered = False
    if attacker:
        try:
            store.put(attacker, "app.zip", tamper_payload, writers)
            tampered = True
        except PermissionError:
            pass
    data = store.objects["app.zip"]
    if pipeline["artifact_store"].get("digest_verification") and hashlib.sha256(data).hexdigest() != digest:
        return {"deployed": None, "tampered": tampered, "result": "deploy aborted: digest mismatch"}
    return {"deployed": data, "tampered": tampered, "result": "deployed"}


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))
