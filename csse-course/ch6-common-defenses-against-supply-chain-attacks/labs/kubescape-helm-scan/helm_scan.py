"""Scan a Helm chart fixture: render a tiny template subset, then check the rendered manifests and the chart metadata.

The renderer supports only `{{ .Values.a.b }}` and `{{ .Values.a.b | default "x" }}`. Real Helm (and Kubescape) do far more.
For the full manifest controls see the sibling lab kubescape-manifest-scan and csse ch4 / 06-ai-devsecops kubernetes.
"""

from __future__ import annotations

import hashlib
import re

import yaml

CHART = {
    "Chart.yaml": "apiVersion: v2\nname: shop-api\nversion: 0.3.0\ndependencies:\n  - {name: redis, version: 17.0.0, repository: \"http://charts.example/stable\"}\n",
    "values.yaml": ("image:\n  repository: shop/api\n  tag: latest\nsecurityContext:\n  privileged: false\n  runAsNonRoot: false\n"
                    "service:\n  type: LoadBalancer\nadminPassword: FAKE-chart-default-pass\n"),
    "templates/deployment.yaml": (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: shop-api}\nspec:\n  template:\n    spec:\n      containers:\n"
        "        - name: api\n          image: {{ .Values.image.repository }}:{{ .Values.image.tag | default \"latest\" }}\n"
        "          env:\n            - {name: ADMIN_PASSWORD, value: \"{{ .Values.adminPassword }}\"}\n"
        "          securityContext: {privileged: {{ .Values.securityContext.privileged }}, runAsNonRoot: {{ .Values.securityContext.runAsNonRoot }}}\n"),
}
HARDENED_OVERRIDES = {"image": {"tag": "1.4.2@sha256:" + "ab" * 32}, "securityContext": {"runAsNonRoot": True}, "adminPassword": ""}


def deep_merge(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def render(template: str, values: dict) -> str:
    def sub(m):
        cur = values
        for part in m.group(1).split("."):
            cur = cur.get(part, "") if isinstance(cur, dict) else ""
        if cur in ("", None) and m.group(2):
            return m.group(2)
        return str(cur).lower() if isinstance(cur, bool) else str(cur)
    return re.sub(r"\{\{\s*\.Values\.([\w.]+)(?:\s*\|\s*default\s+\"([^\"]*)\")?\s*\}\}", sub, template)


def render_chart(chart: dict, overrides: dict | None = None):
    values = deep_merge(yaml.safe_load(chart["values.yaml"]), overrides or {})
    docs = []
    for path, text in chart.items():
        if path.startswith("templates/"):
            docs += [d for d in yaml.safe_load_all(render(text, values)) if d]
    return values, docs


def check_chart(chart: dict, overrides: dict | None = None, prov_digest: str | None = None):
    values, docs = render_chart(chart, overrides)
    f = []
    meta = yaml.safe_load(chart["Chart.yaml"])
    for dep in meta.get("dependencies", []):
        if dep["repository"].startswith("http://"):
            f.append(("HELM-01", "high", f"dependency {dep['name']} fetched over plain HTTP"))
    if "Chart.lock" not in chart:
        f.append(("HELM-02", "medium", "no Chart.lock: dependency versions/digests not pinned"))
    if prov_digest is None:
        f.append(("HELM-03", "medium", "no provenance (.prov) verified: chart origin not checked"))
    elif prov_digest != hashlib.sha256(chart["Chart.yaml"].encode()).hexdigest():
        f.append(("HELM-03", "critical", "provenance digest does not match chart"))
    for d in docs:
        if d["kind"] != "Deployment":
            continue
        for c in d["spec"]["template"]["spec"]["containers"]:
            img = c["image"]
            if "@sha256:" not in img and img.endswith(":latest"):
                f.append(("HELM-04", "medium", f"rendered image '{img}' uses a mutable tag"))
            sc = c.get("securityContext", {})
            if sc.get("privileged"):
                f.append(("HELM-05", "critical", "rendered container is privileged"))
            if not sc.get("runAsNonRoot"):
                f.append(("HELM-06", "high", "rendered container may run as root"))
            for e in c.get("env", []):
                if "PASSWORD" in e["name"] and e.get("value"):
                    f.append(("HELM-07", "high", f"{e['name']} rendered as plain text (chart default value is a secret)"))
    if values.get("service", {}).get("type") == "LoadBalancer":
        f.append(("HELM-08", "low", "default service type exposes a public load balancer"))
    return f
