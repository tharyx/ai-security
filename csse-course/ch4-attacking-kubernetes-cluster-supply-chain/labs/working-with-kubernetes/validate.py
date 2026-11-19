"""Validate that Deployment, Service and Ingress fit together (no cluster).

Most "it deploys but nothing works" bugs, and several security gaps, are wiring mistakes:
selectors that match nothing, wrong ports, an Ingress pointing at a missing Service, no TLS.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Issue:
    code: str
    severity: str
    where: str
    message: str


def load(path: str | Path) -> list[dict]:
    return [d for d in yaml.safe_load_all(Path(path).read_text()) if d]


def _meta(d: dict) -> tuple[str, str]:
    m = d.get("metadata") or {}
    return m.get("namespace", "default"), m.get("name", "?")


def _selector_matches(selector: dict, labels: dict) -> bool:
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def validate(docs: list[dict]) -> list[Issue]:
    issues: list[Issue] = []
    deployments = [d for d in docs if d["kind"] == "Deployment"]
    services = [d for d in docs if d["kind"] == "Service"]
    ingresses = [d for d in docs if d["kind"] == "Ingress"]

    for d in deployments:
        ns, name = _meta(d)
        spec = d["spec"]
        tmpl_labels = (spec.get("template", {}).get("metadata") or {}).get("labels") or {}
        sel = (spec.get("selector") or {}).get("matchLabels") or {}
        if not _selector_matches(sel, tmpl_labels):
            issues.append(Issue("WK-001", "HIGH", f"Deployment/{ns}/{name}", "spec.selector does not match template labels (the API server rejects this; fix before apply)"))
        for c in spec["template"]["spec"].get("containers", []):
            if not c.get("readinessProbe"):
                issues.append(Issue("WK-002", "LOW", f"Deployment/{ns}/{name}", f"container {c['name']} has no readinessProbe: traffic can reach it before it is ready"))
            if ":" not in c["image"].rsplit("/", 1)[-1] or c["image"].endswith(":latest"):
                issues.append(Issue("WK-003", "MEDIUM", f"Deployment/{ns}/{name}", f"image {c['image']} is untagged or latest"))

    for s in services:
        ns, name = _meta(s)
        sel = s["spec"].get("selector") or {}
        targets = [d for d in deployments if _meta(d)[0] == ns and _selector_matches(sel, (d["spec"]["template"].get("metadata") or {}).get("labels") or {})]
        if not targets:
            issues.append(Issue("WK-010", "HIGH", f"Service/{ns}/{name}", "selector matches no pod template: the Service has no endpoints"))
            continue
        ports = {p["containerPort"] for d in targets for c in d["spec"]["template"]["spec"]["containers"] for p in c.get("ports", [])}
        port_names = {p.get("name") for d in targets for c in d["spec"]["template"]["spec"]["containers"] for p in c.get("ports", [])}
        for p in s["spec"].get("ports", []):
            tp = p.get("targetPort", p["port"])
            if (isinstance(tp, int) and tp not in ports) or (isinstance(tp, str) and tp not in port_names):
                issues.append(Issue("WK-011", "HIGH", f"Service/{ns}/{name}", f"targetPort {tp} is not exposed by any container"))
        if s["spec"].get("type") in ("NodePort", "LoadBalancer"):
            issues.append(Issue("WK-012", "MEDIUM", f"Service/{ns}/{name}", f"type {s['spec']['type']} is reachable from outside the cluster; confirm this is intended"))

    svc_index = {_meta(s): s for s in services}
    for ing in ingresses:
        ns, name = _meta(ing)
        spec = ing["spec"]
        if not spec.get("tls"):
            issues.append(Issue("WK-020", "HIGH", f"Ingress/{ns}/{name}", "no TLS section: traffic is plain HTTP"))
        for rule in spec.get("rules", []):
            for path in (rule.get("http") or {}).get("paths", []):
                backend = path["backend"]["service"]
                svc = svc_index.get((ns, backend["name"]))
                if not svc:
                    issues.append(Issue("WK-021", "HIGH", f"Ingress/{ns}/{name}", f"backend Service {backend['name']} does not exist"))
                elif backend.get("port", {}).get("number") not in {p["port"] for p in svc["spec"].get("ports", [])}:
                    issues.append(Issue("WK-022", "HIGH", f"Ingress/{ns}/{name}", f"backend port {backend.get('port')} is not a port of Service {backend['name']}"))
        annotations = (ing.get("metadata") or {}).get("annotations") or {}
        if annotations.get("nginx.ingress.kubernetes.io/ssl-redirect") == "false":
            issues.append(Issue("WK-023", "MEDIUM", f"Ingress/{ns}/{name}", "ssl-redirect is disabled"))
    return issues
