"""Static analysis of Kubernetes manifests and Helm charts (offline).

Layer 1: the module-06 manifest checker (k8s_policy.py), loaded by path, for pod hardening, secrets, RBAC, network.
Layer 2: Helm-specific supply chain checks on a chart: dependency repositories, lock file, provenance file,
         hooks, values defaults, and a check of what the chart RENDERS to under given values.
Real tools: kube-linter, Kubescape, Trivy config (`trivy config`, `trivy k8s`), Checkov, Polaris, helm lint.
"""
from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


k8s_policy = _load("csse4_k8s_policy_static", REPO / "06-ai-devsecops/kubernetes/lab/k8s_policy.py")
helm_render = _load("csse4_helm_render", HERE / "helm_render.py")

TRUSTED_REPOS = ("https://charts.corp.example",)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    where: str
    message: str


def check_manifests(*paths: str | Path) -> list[Finding]:
    return [Finding(f.rule_id, f.severity, f.obj, f.message) for f in k8s_policy.check(k8s_policy.load_docs(*paths))]


def check_docs(docs: list[dict]) -> list[Finding]:
    return [Finding(f.rule_id, f.severity, f.obj, f.message) for f in k8s_policy.check(docs)]


def chart_checks(chart_dir: str | Path, rendered: list[dict], trusted_repos: tuple[str, ...] = TRUSTED_REPOS) -> list[Finding]:
    chart_dir = Path(chart_dir)
    meta = yaml.safe_load((chart_dir / "Chart.yaml").read_text())
    values = yaml.safe_load((chart_dir / "values.yaml").read_text()) or {}
    out: list[Finding] = []
    for dep in meta.get("dependencies") or []:
        repo = dep.get("repository", "")
        if repo.startswith("http://"):
            out.append(Finding("HELM-001", "HIGH", f"dependency {dep['name']}", f"repository {repo} uses plain HTTP: tampering in transit"))
        elif repo and repo not in trusted_repos and not repo.startswith("oci://registry.corp.example"):
            out.append(Finding("HELM-001", "MEDIUM", f"dependency {dep['name']}", f"repository {repo} is not on the trusted list"))
        if any(ch in dep.get("version", "") for ch in "x*^~<>"):
            out.append(Finding("HELM-002", "MEDIUM", f"dependency {dep['name']}", f"version range '{dep['version']}' is not pinned; commit Chart.lock and verify digests"))
    if meta.get("dependencies") and not (chart_dir / "Chart.lock").exists():
        out.append(Finding("HELM-003", "MEDIUM", "chart", "no Chart.lock: dependency versions and digests are not locked"))
    if not list(chart_dir.glob("*.prov")):
        out.append(Finding("HELM-004", "MEDIUM", "chart", "no provenance file (.prov): chart signature cannot be verified with `helm verify`; consider OCI + cosign"))
    if str(values.get("image", {}).get("tag", "")) in ("latest", ""):
        out.append(Finding("HELM-005", "MEDIUM", "values.yaml", "default image tag is 'latest' (pin a tag and a digest)"))
    if values.get("securityContext", {}).get("privileged"):
        out.append(Finding("HELM-006", "HIGH", "values.yaml", "chart default sets privileged: true; defaults should be secure"))
    for d in rendered:
        ann = (d.get("metadata") or {}).get("annotations") or {}
        if "helm.sh/hook" in ann:
            spec = k8s_policy.pod_spec(d) if hasattr(k8s_policy, "pod_spec") else {}
            risky = spec.get("hostNetwork") or any((c.get("securityContext") or {}).get("privileged") for c in spec.get("containers", []))
            if risky:
                out.append(Finding("HELM-007", "HIGH", f"{d['kind']}/{d['metadata']['name']}", f"hook {ann['helm.sh/hook']} runs privileged or on the host network during install/upgrade"))
        if d["kind"] in ("ClusterRoleBinding", "RoleBinding") and d["roleRef"]["name"] == "cluster-admin":
            out.append(Finding("HELM-008", "CRITICAL", f"{d['kind']}/{d['metadata']['name']}", "chart installs a cluster-admin binding"))
    for tpl in (chart_dir / "templates").glob("*.yaml"):
        if "lookup " in tpl.read_text():
            out.append(Finding("HELM-009", "MEDIUM", f"templates/{tpl.name}", "uses `lookup`: the chart reads live cluster objects at render time"))
    return out


def analyse_chart(chart_dir: str | Path, overrides: dict | None = None) -> list[Finding]:
    rendered = helm_render.render_chart(chart_dir, overrides)
    return check_docs(rendered) + chart_checks(chart_dir, rendered)
