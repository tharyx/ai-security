"""Kubescape-style manifest controls over YAML fixtures. Local control IDs (KL-xx) are NOT Kubescape's own IDs."""

from __future__ import annotations

import yaml

BAD = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: web
          image: shop/web:latest
          env:
            - {name: DB_PASSWORD, value: "FAKE-plaintext"}
          securityContext: {privileged: true}
"""

GOOD = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: shop}
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: api
          image: shop/api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          resources: {limits: {cpu: "500m", memory: 256Mi}}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
"""

CONTROLS = {
    "KL-01": ("Privileged container", "critical"), "KL-02": ("Host network/PID/IPC", "high"),
    "KL-03": ("Runs as root (runAsNonRoot not set)", "high"), "KL-04": ("allowPrivilegeEscalation not disabled", "medium"),
    "KL-05": ("Writable root filesystem", "medium"), "KL-06": ("Capabilities not dropped", "medium"),
    "KL-07": ("No resource limits", "medium"), "KL-08": ("Image tag is mutable (latest or missing)", "medium"),
    "KL-09": ("Secret-looking env var in plain text", "high"), "KL-10": ("Service account token auto-mounted", "low"),
    "KL-11": ("hostPath volume", "high"),
}
FRAMEWORKS = {"workload-hardening": ["KL-01", "KL-02", "KL-03", "KL-04", "KL-05", "KL-06", "KL-07", "KL-10"],
              "supply-chain": ["KL-08", "KL-09"], "all": list(CONTROLS)}
PODSPEC_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"}


def pod_spec(doc):
    if doc["kind"] == "Pod":
        return doc["spec"]
    if doc["kind"] in PODSPEC_KINDS:
        return doc["spec"]["template"]["spec"]
    if doc["kind"] == "CronJob":
        return doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    return None


def check_doc(doc: dict):
    ps = pod_spec(doc)
    if ps is None:
        return []
    name = f"{doc['kind']}/{doc['metadata']['name']}"
    fails = []
    pod_sc = ps.get("securityContext", {})
    if ps.get("hostNetwork") or ps.get("hostPID") or ps.get("hostIPC"):
        fails.append(("KL-02", name, "pod"))
    if ps.get("automountServiceAccountToken", True):
        fails.append(("KL-10", name, "pod"))
    if any("hostPath" in v for v in ps.get("volumes", [])):
        fails.append(("KL-11", name, "pod"))
    for c in ps.get("containers", []) + ps.get("initContainers", []):
        sc = c.get("securityContext", {})
        where = f"container {c['name']}"
        if sc.get("privileged"):
            fails.append(("KL-01", name, where))
        if not (sc.get("runAsNonRoot") or pod_sc.get("runAsNonRoot")):
            fails.append(("KL-03", name, where))
        if sc.get("allowPrivilegeEscalation", True):
            fails.append(("KL-04", name, where))
        if not sc.get("readOnlyRootFilesystem"):
            fails.append(("KL-05", name, where))
        if "ALL" not in [x.upper() for x in sc.get("capabilities", {}).get("drop", [])]:
            fails.append(("KL-06", name, where))
        if not c.get("resources", {}).get("limits"):
            fails.append(("KL-07", name, where))
        img = c["image"]
        if "@sha256:" not in img and (":" not in img.split("/")[-1] or img.endswith(":latest")):
            fails.append(("KL-08", name, where))
        for e in c.get("env", []):
            if any(k in e["name"].upper() for k in ("PASSWORD", "SECRET", "TOKEN", "KEY")) and "value" in e:
                fails.append(("KL-09", name, where))
    return fails


def scan(text: str, framework: str = "all", exceptions=()):
    wanted = set(FRAMEWORKS[framework])
    res = []
    for doc in yaml.safe_load_all(text):
        if doc:
            res += [f for f in check_doc(doc) if f[0] in wanted and (f[0], f[1]) not in exceptions]
    return res


def compliance_score(fails, framework: str = "all") -> int:
    """Percent of framework controls with no failures (simplified; Kubescape's own scoring differs)."""
    ctrl = set(FRAMEWORKS[framework])
    failed = {f[0] for f in fails}
    return round(100 * (len(ctrl) - len(failed & ctrl)) / len(ctrl))
