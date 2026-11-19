"""Inspect Docker daemon activity: analyse `docker events --format '{{json .}}'` lines and container logs (fixtures).

Real sources (hedged): `docker events`, `docker logs`, the daemon log (journalctl -u docker), auditd rules on the socket.
This lab turns a stream of events into a timeline and raises alerts for suspicious patterns.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

ALLOWED_REGISTRIES = ("registry.example", "docker.io/library", "ghcr.io/ourorg")


def parse(lines: list[str]) -> list[dict]:
    events = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        e = json.loads(raw)
        e["ts"] = datetime.fromtimestamp(e["time"], tz=timezone.utc)
        e["actor"] = e.get("Actor", {}).get("Attributes", {})
        events.append(e)
    return sorted(events, key=lambda e: e["time"])


def timeline(events: list[dict]) -> list[str]:
    out = []
    for e in events:
        a = e["actor"]
        name = a.get("name", a.get("image", e.get("id", "?")))[:24]
        out.append(f"{e['ts']:%H:%M:%S} {e['Type']}.{e['Action']:<14} {name}")
    return out


def detect(events: list[dict]) -> list[dict]:
    alerts = []

    def add(sev, rule, e, msg):
        alerts.append({"severity": sev, "rule": rule, "time": f"{e['ts']:%H:%M:%S}", "message": msg})

    restarts = Counter()
    for e in events:
        a, act = e["actor"], e["Action"]
        name = a.get("name", "")
        if e["Type"] == "container" and act == "create":
            if a.get("privileged") == "true":
                add("CRITICAL", "EVT-PRIV", e, f"privileged container created: {name} ({a.get('image')})")
            if "docker.sock" in a.get("mounts", ""):
                add("CRITICAL", "EVT-SOCK", e, f"container {name} created with docker.sock mounted")
            if a.get("mounts", "").startswith("/:") or ",/:" in a.get("mounts", ""):
                add("HIGH", "EVT-HOSTROOT", e, f"container {name} mounts the host root")
        if e["Type"] == "container" and act.startswith("exec_create"):
            add("MEDIUM", "EVT-EXEC", e, f"interactive exec into {name}: {a.get('execID', '')[:6]} {a.get('cmd', '')}")
        if e["Type"] == "image" and act == "pull":
            ref = a.get("name", "")
            if not ref.startswith(ALLOWED_REGISTRIES):
                add("HIGH", "EVT-PULL", e, f"image pulled from an unapproved source: {ref}")
        if e["Type"] == "container" and act == "oom":
            add("MEDIUM", "EVT-OOM", e, f"{name} killed by the out-of-memory killer: possible DoS or leak")
        if e["Type"] == "container" and act == "die" and a.get("exitCode") not in ("0", None):
            restarts[name] += 1
        if e["Type"] == "image" and act == "tag":
            add("LOW", "EVT-TAG", e, f"tag moved: {a.get('name')}")
        if e["Type"] == "daemon" and act == "reload":
            add("MEDIUM", "EVT-DAEMON", e, "daemon configuration reloaded: check daemon.json for changes")
    for name, n in restarts.items():
        if n >= 3:
            alerts.append({"severity": "MEDIUM", "rule": "EVT-CRASHLOOP", "time": "-", "message": f"{name} exited with an error {n} times: crash loop or an attacker probing"})
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    return sorted(alerts, key=lambda a: (order.index(a["severity"]), a["time"]))


def scan_logs(lines: list[str]) -> list[str]:
    patterns = {"authentication failure": "repeated auth failures", "permission denied": "permission probing", "segfault": "possible exploitation attempt or bug",
                "base64 -d": "encoded payload execution"}
    found = []
    for n, line in enumerate(lines, 1):
        for p, why in patterns.items():
            if p in line.lower():
                found.append(f"line {n}: {why}: {line.strip()[:60]}")
    return found
