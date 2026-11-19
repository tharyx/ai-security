"""CDE 7 lab: audit a Docker daemon and host. Shares the auditor from ../cis-docker-compliance.

Adds: a `docker info` text parser (cross-check), grouping by section, a remediation
list and a gate. Fixtures differ from the CIS lab: a build server before and after
hardening.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

_p = Path(__file__).resolve().parents[1] / "cis-docker-compliance" / "cis_audit.py"
_spec = importlib.util.spec_from_file_location("dso_ch11_cis_audit_shared", _p)
cis = importlib.util.module_from_spec(_spec)
sys.modules["dso_ch11_cis_audit_shared"] = cis
_spec.loader.exec_module(cis)

REMEDIATION = {
    "1.2.2": "Remove unapproved users from the docker group (it is root-equivalent).",
    "2.6": "Use fd:// or a unix socket; if TCP is required set tlsverify + CA + server cert/key.",
    "2.8": 'Set "userns-remap": "default" in /etc/docker/daemon.json (plan for volume ownership).',
    "3.16": "chmod 660 /var/run/docker.sock; owner root:docker.",
    "5.4": "Drop --privileged; add only the specific capability needed.",
    "5.31": "Never mount docker.sock; use a rootless builder (BuildKit/kaniko) in CI.",
}


def parse_docker_info(text: str) -> dict:
    """Pull a few facts out of `docker info` text output (as shown to humans)."""
    d: dict = {}
    for line in text.splitlines():
        m = re.match(r"\s*([A-Za-z ]+):\s*(.*)$", line)
        if not m:
            continue
        k, v = m.group(1).strip(), m.group(2).strip()
        if k == "Logging Driver":
            d["log-driver"] = v
        elif k == "Live Restore Enabled":
            d["live-restore"] = v.lower() == "true"
        elif k == "Storage Driver":
            d["storage-driver"] = v
        elif k == "Insecure Registries":
            d["insecure"] = True
    sec = re.search(r"Security Options:\s*\n((?:\s{2,}.*\n?)+)", text)
    d["security-options"] = [s.strip().split()[0] for s in sec.group(1).splitlines() if s.strip() and not s.strip().startswith("Profile")] if sec else []
    return d


def cross_check(bundle: dict, info: dict) -> list[str]:
    """Differences between the configured daemon.json and what the running daemon reports."""
    out = []
    if info.get("live-restore") != bool(bundle["daemon"].get("live-restore")):
        out.append("live-restore: running daemon differs from daemon.json (restart pending?)")
    if bundle["daemon"].get("userns-remap") and not any("userns" in s for s in info.get("security-options", [])):
        out.append("userns-remap configured but not active in the running daemon")
    if "seccomp" not in str(info.get("security-options")):
        out.append("seccomp not reported by the running daemon")
    return out


def run(bundle: dict, fail_on: str = "high") -> dict:
    res = cis.audit(bundle)
    fails = [r for r in res if not r.passed]
    return {
        "score": cis.score(res), "weighted": cis.weighted_score(res),
        "sections": cis.by_section(res), "exit_code": cis.exit_code(res, fail_on),
        "remediation": [f"{r.id}: {REMEDIATION[r.id]}" for r in fails if r.id in REMEDIATION],
        "failed": [r.id for r in fails],
    }
