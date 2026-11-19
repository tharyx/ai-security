"""Image-based attacks, analysed offline: (1) secrets an attacker can pull out of an image and (2) an exploit-path
analysis for vulnerable components (which flaw is actually reachable, and how far does it get the attacker?).

No exploit code. A 'path' is a sentence chain: entry point -> flaw -> privilege -> impact.
Vulnerability IDs are FIXTURE ids; real work uses Trivy/Grype data and CVE/KEV/EPSS (verify at source).
"""
from __future__ import annotations

import re
from dataclasses import dataclass


def canary_token() -> str:
    return "ia" + "-fake-" + "tok-" + "5b3a77"


def sample_image() -> dict:
    return {
        "name": "shop/web:2.3",
        "history": ["FROM python:3.9", f"ENV SERVICE_TOKEN={canary_token()}", "RUN pip install flask==1.0 pillow==8.0 requests", "EXPOSE 8080"],
        "files": {"/app/.git/config": "[remote origin]\n\turl = https://user:canary-git-pw@git.example.invalid/shop.git\n",
                  "/app/app.py": "print('hello')\n"},
        "exposed_ports": [8080],
        "user": "root",
        "components": [
            {"name": "flask", "version": "1.0", "listens_public": True, "role": "web framework"},
            {"name": "pillow", "version": "8.0", "listens_public": False, "role": "image processing of user uploads"},
            {"name": "requests", "version": "2.31.0", "listens_public": False, "role": "outbound HTTP"},
            {"name": "internal-metrics", "version": "0.3", "listens_public": False, "role": "debug endpoint on localhost"},
        ],
        "runtime": {"privileged": False, "docker_sock": True, "network": "bridge"},
    }


VULN_DB = [
    {"id": "FIXTURE-A1", "component": "flask", "affects_below": "2.0", "kind": "RCE", "needs": "network", "cvss": 9.8,
     "summary": "fixture: debug console reachable remotely"},
    {"id": "FIXTURE-A2", "component": "pillow", "affects_below": "9.0", "kind": "memory corruption", "needs": "attacker-supplied file", "cvss": 7.8,
     "summary": "fixture: crafted image triggers heap overflow"},
    {"id": "FIXTURE-A3", "component": "requests", "affects_below": "2.31.0", "kind": "info leak", "needs": "network", "cvss": 6.1,
     "summary": "fixture: fixed in this version"},
    {"id": "FIXTURE-A4", "component": "internal-metrics", "affects_below": "1.0", "kind": "RCE", "needs": "local access", "cvss": 8.8,
     "summary": "fixture: only reachable from inside"},
]


def _v(s: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", s))


def extract_secrets(img: dict) -> list[dict]:
    out = []
    for step in img["history"]:
        m = re.search(r"(?i)\b(\w*(?:token|password|secret|key)\w*)=(\S+)", step)
        if m:
            out.append({"where": "image history", "name": m.group(1), "how": "docker history --no-trunc IMAGE (no need to run it)"})
    for path, content in img["files"].items():
        if re.search(r"://[^/\s:]+:[^@\s]+@", content):
            out.append({"where": path, "name": "credentials in a URL", "how": "docker save + tar, or docker cp from a stopped container"})
    return out


@dataclass
class Path:
    vuln_id: str
    component: str
    reachable: bool
    why: str
    steps: list[str]
    priority: str


def exploit_paths(img: dict, db: list[dict] = VULN_DB) -> list[Path]:
    comps = {c["name"]: c for c in img["components"]}
    rt, out = img["runtime"], []
    for v in db:
        c = comps.get(v["component"])
        if not c or not _v(c["version"]) < _v(v["affects_below"]):
            continue
        reach, why = False, ""
        if v["needs"] == "network":
            reach = bool(c["listens_public"] and img["exposed_ports"])
            why = "component serves the exposed port" if reach else "component is not network-facing"
        elif v["needs"] == "attacker-supplied file":
            reach = True
            why = f"component processes user input ({c['role']})"
        else:
            reach, why = False, "needs a foothold inside the container first: a second step, not an entry point"
        port = f"internet to port {img['exposed_ports'][0]}" if img["exposed_ports"] else "no published port"
        steps = [f"entry: {port if v['needs'] != 'local access' else 'existing foothold'}",
                 f"flaw: {v['id']} {v['kind']} in {c['name']} {c['version']}"]
        if img["user"] == "root":
            steps.append("privilege: code runs as root inside the container")
        if rt.get("docker_sock"):
            steps.append("pivot: mounted docker.sock lets that root start a host-level container")
        elif rt.get("privileged"):
            steps.append("pivot: privileged mode removes the container boundary")
        impact = "host compromise" if (rt.get("docker_sock") or rt.get("privileged")) and v["kind"] in ("RCE", "memory corruption") else "container compromise"
        steps.append(f"impact: {impact}")
        prio = "FIX NOW" if reach and v["cvss"] >= 7 else "FIX SOON" if reach else "BACKLOG (not directly reachable)"
        out.append(Path(v["id"], c["name"], reach, why, steps, prio))
    order = {"FIX NOW": 0, "FIX SOON": 1}
    return sorted(out, key=lambda p: order.get(p.priority, 2))
