"""Image scanning for Kubernetes manifests against a LOCAL vulnerability database fixture (offline).

Real scanners (Trivy, Grype, Kubescape, `trivy k8s`) download a vulnerability DB and inspect image layers. Here the
"DB" is a JSON file that maps image references to findings. All IDs are synthetic (CVE-2099-xxxx): they are not
real vulnerabilities. What is real is the workflow: extract every image from the manifests, resolve it, apply a
gate, and insist on a digest so that the thing you scanned is the thing that runs.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
DIGEST = re.compile(r"@(sha256:[0-9a-f]{64})$")
WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


@dataclass(frozen=True)
class Policy:
    allowed_registries: tuple[str, ...] = ("registry.corp.example",)
    max_critical: int = 0
    max_high: int = 2
    require_digest: bool = True


@dataclass
class ImageReport:
    ref: str
    where: list[str] = field(default_factory=list)
    vulns: list[dict] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        c = {k: 0 for k in SEV_ORDER}
        for v in self.vulns:
            c[v["severity"]] += 1
        return c


def pod_spec(doc: dict) -> dict:
    spec = doc.get("spec") or {}
    if doc["kind"] == "Pod":
        return spec
    if doc["kind"] == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec") or {}


def extract_images(docs: list[dict]) -> dict[str, list[str]]:
    """image ref -> list of workloads that use it (init and ephemeral containers included)."""
    out: dict[str, list[str]] = {}
    for d in docs:
        if d["kind"] not in WORKLOADS:
            continue
        spec = pod_spec(d)
        for c in (spec.get("initContainers") or []) + (spec.get("containers") or []):
            out.setdefault(c["image"], []).append(f"{d['kind']}/{d['metadata']['name']}:{c['name']}")
    return out


def load_db(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())


def lookup(ref: str, db: dict) -> list[dict] | None:
    """Digest refs are looked up by digest first; tag refs by repo:tag. None means 'never scanned'."""
    m = DIGEST.search(ref)
    if m and m.group(1) in db["by_digest"]:
        return db["by_digest"][m.group(1)]
    return db["by_tag"].get(canonical(DIGEST.sub("", ref)))


def canonical(ref: str) -> str:
    """nginx:1.27 -> docker.io/library/nginx:1.27 (Docker Hub shortcuts expanded)."""
    parts = ref.split("/")
    if len(parts) == 1 or not ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = ["docker.io"] + parts
    if parts[0] == "docker.io" and len(parts) == 2:
        parts.insert(1, "library")
    return "/".join(parts)


def registry_of(ref: str) -> str:
    first = ref.split("/")[0]
    return first if ("/" in ref and ("." in first or ":" in first or first == "localhost")) else "docker.io"


def scan_manifests(docs: list[dict], db: dict, policy: Policy = Policy()) -> list[ImageReport]:
    reports = []
    for ref, where in extract_images(docs).items():
        r = ImageReport(ref, where)
        found = lookup(ref, db)
        if found is None:
            r.problems.append("never scanned: no entry in the vulnerability database")
        else:
            r.vulns = found
        if registry_of(ref) not in policy.allowed_registries:
            r.problems.append(f"registry {registry_of(ref)} is not allowed")
        if policy.require_digest and not DIGEST.search(ref):
            r.problems.append("not pinned by digest: the scanned image may differ from what runs")
        c = r.counts
        if c["CRITICAL"] > policy.max_critical:
            r.problems.append(f"{c['CRITICAL']} critical vulnerabilities (max {policy.max_critical})")
        if c["HIGH"] > policy.max_high:
            r.problems.append(f"{c['HIGH']} high vulnerabilities (max {policy.max_high})")
        reports.append(r)
    return reports


def gate(reports: list[ImageReport]) -> bool:
    return all(not r.problems for r in reports)


def fixable(report: ImageReport) -> list[str]:
    return [f"{v['package']} -> {v['fixed']}" for v in report.vulns if v.get("fixed")]
