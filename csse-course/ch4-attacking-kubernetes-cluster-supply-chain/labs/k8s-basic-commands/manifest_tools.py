"""Practice the ideas behind basic kubectl commands on plain YAML (no cluster, no kubectl).

    kubectl get <kind>             -> get_table(docs, "Deployment")
    kubectl get -o jsonpath=...    -> jsonpath(doc, "spec.template.spec.containers[0].image")
    kubectl describe               -> describe(doc)
    kubectl apply --dry-run        -> parse errors show up in load_all

Always parse with yaml.safe_load_all. yaml.load on untrusted YAML can construct arbitrary Python objects.
"""
from __future__ import annotations

import re

import yaml

PATH_PART = re.compile(r"([A-Za-z0-9_-]+)|\[(\d+)\]")
WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


def load_all(text: str) -> list[dict]:
    docs = [d for d in yaml.safe_load_all(text) if d]
    for d in docs:
        if not isinstance(d, dict) or "kind" not in d or "apiVersion" not in d:
            raise ValueError("every document needs apiVersion and kind")
    return docs


def name_of(doc: dict) -> str:
    return (doc.get("metadata") or {}).get("name", "?")


def namespace_of(doc: dict) -> str:
    return (doc.get("metadata") or {}).get("namespace", "default")


def get_table(docs: list[dict], kind: str, namespace: str | None = None) -> list[tuple[str, str, str]]:
    """Rows of (namespace, name, extra) like `kubectl get <kind> -A`."""
    rows = []
    for d in docs:
        if d["kind"].lower() != kind.lower() or (namespace and namespace_of(d) != namespace):
            continue
        extra = ""
        if d["kind"] == "Deployment":
            extra = f"replicas={d['spec'].get('replicas', 1)}"
        elif d["kind"] == "Service":
            extra = f"type={d['spec'].get('type', 'ClusterIP')}"
        rows.append((namespace_of(d), name_of(d), extra))
    return rows


def jsonpath(doc, path: str):
    """Tiny JSONPath: dotted keys and [index], e.g. spec.template.spec.containers[0].image."""
    cur = doc
    for key, idx in PATH_PART.findall(path):
        if key:
            cur = cur[key] if isinstance(cur, dict) and key in cur else None
        else:
            cur = cur[int(idx)] if isinstance(cur, list) and int(idx) < len(cur) else None
        if cur is None:
            return None
    return cur


def pod_spec(doc: dict) -> dict:
    spec = doc.get("spec") or {}
    if doc["kind"] == "Pod":
        return spec
    if doc["kind"] == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec") or {}


def images(docs: list[dict]) -> list[tuple[str, str]]:
    out = []
    for d in docs:
        if d["kind"] in WORKLOADS:
            for c in (pod_spec(d).get("initContainers") or []) + (pod_spec(d).get("containers") or []):
                out.append((f"{d['kind']}/{name_of(d)}", c["image"]))
    return out


def missing_limits(docs: list[dict]) -> list[str]:
    out = []
    for d in docs:
        if d["kind"] in WORKLOADS:
            for c in pod_spec(d).get("containers") or []:
                lim = (c.get("resources") or {}).get("limits") or {}
                if "memory" not in lim or "cpu" not in lim:
                    out.append(f"{d['kind']}/{name_of(d)}:{c['name']}")
    return out


def describe(doc: dict) -> str:
    lines = [f"Name:       {name_of(doc)}", f"Namespace:  {namespace_of(doc)}", f"Kind:       {doc['kind']}"]
    labels = (doc.get("metadata") or {}).get("labels") or {}
    lines.append("Labels:     " + (", ".join(f"{k}={v}" for k, v in sorted(labels.items())) or "<none>"))
    return "\n".join(lines)
