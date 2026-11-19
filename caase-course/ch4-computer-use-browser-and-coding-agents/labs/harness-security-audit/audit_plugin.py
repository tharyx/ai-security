"""A SecureClaw-style security audit plugin (a course teaching tool, not the real SecureClaw).

Each check has an id, a weight, an OWASP Top 10 for Agentic Applications 2026 id (ASI)
and a MITRE ATLAS technique NAME. ATLAS names and IDs change; verify at atlas.mitre.org.
The real SecureClaw reportedly has dozens of checks; this one has twelve.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

SECRET_NAME_RE = re.compile(r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)", re.IGNORECASE)


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    weight: int
    asi: str
    atlas: str
    fn: Callable[[dict], tuple[bool, str]]
    fix: str


def _g(cfg: dict, *path, default=None):
    cur = cfg
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def c_sandbox(cfg):
    ok = bool(_g(cfg, "sandbox", "enabled", default=False))
    return ok, "sandbox enabled" if ok else "sandbox is off: the agent runs with the user's full rights"


def c_non_root(cfg):
    ok = _g(cfg, "sandbox", "run_as_root", default=True) is False
    return ok, "runs as non-root" if ok else "agent process runs as root/admin"


def c_workspace(cfg):
    ok = bool(_g(cfg, "sandbox", "workspace_only", default=False))
    return ok, "file access limited to the workspace" if ok else "file access is not limited to the workspace"


def c_egress(cfg):
    mode = _g(cfg, "network", "egress_mode", default="allow_all")
    allow = _g(cfg, "network", "egress_allowlist", default=[])
    ok = mode == "allowlist" and bool(allow) and "*" not in allow
    return ok, "egress allowlist in force" if ok else f"egress mode is {mode!r} with {len(allow)} allowed hosts"


def c_approvals(cfg):
    ok = _g(cfg, "approvals", "destructive_actions") == "always"
    return ok, "destructive actions need approval" if ok else "destructive actions run without approval"


def c_timeout(cfg):
    ok = _g(cfg, "approvals", "timeout_action") == "deny"
    return ok, "approval timeout means deny" if ok else "approval timeout does not deny"


def c_skill_sig(cfg):
    ok = bool(_g(cfg, "skills", "verify_signatures", default=False)) and not _g(cfg, "skills", "allow_unsigned", default=True)
    return ok, "skill signatures required" if ok else "unsigned skills may be installed"


def c_skill_pin(cfg):
    ok = bool(_g(cfg, "skills", "pinned", default=False)) and not _g(cfg, "skills", "auto_update", default=True)
    return ok, "skills pinned, no auto-update" if ok else "skills auto-update or are not pinned"


def c_env(cfg):
    bad = [k for k, v in (_g(cfg, "env", default={}) or {}).items() if SECRET_NAME_RE.search(k) and v]
    return not bad, "no secrets in the agent environment" if not bad else f"secrets in environment: {sorted(bad)}"


def c_logging(cfg):
    ok = bool(_g(cfg, "logging", "enabled", default=False)) and bool(_g(cfg, "logging", "tamper_evident", default=False))
    return ok, "tamper-evident logging on" if ok else "logging is off or not tamper-evident"


def c_models(cfg):
    allow = set(_g(cfg, "models", "provider_allowlist", default=[]))
    used = set(_g(cfg, "models", "providers_in_use", default=[]))
    ok = bool(allow) and used <= allow
    return ok, "model providers are allowlisted" if ok else f"providers not allowlisted: {sorted(used - allow)}"


def c_gateway(cfg):
    ok = _g(cfg, "gateway", "bind") in ("127.0.0.1", "localhost", "::1") and bool(_g(cfg, "gateway", "auth_token"))
    return ok, "gateway on loopback with auth" if ok else "gateway is exposed or has no auth"


CHECKS: list[Check] = [
    Check("SB-01", "Sandbox enabled", 10, "ASI05", "Command and Scripting Interpreter (via agent tools)", c_sandbox, "enable container or kernel sandboxing"),
    Check("SB-02", "Non-root process", 5, "ASI05", "Privilege Escalation", c_non_root, "run as an unprivileged user"),
    Check("SB-03", "Workspace-only file access", 8, "ASI02", "Data from Local System", c_workspace, "restrict file tools to the project directory"),
    Check("NET-01", "Egress allowlist", 10, "ASI02", "Exfiltration over Web Services", c_egress, "deny by default; allow only named hosts"),
    Check("HITL-01", "Approval for destructive actions", 10, "ASI09", "AI Agent Tool Invocation", c_approvals, "require a human approval for irreversible actions"),
    Check("HITL-02", "Approval timeout denies", 4, "ASI09", "AI Agent Tool Invocation", c_timeout, "set timeout_action to deny"),
    Check("SUP-01", "Skill signature verification", 10, "ASI04", "Supply Chain Compromise", c_skill_sig, "verify signatures and refuse unsigned skills"),
    Check("SUP-02", "Skills pinned", 5, "ASI04", "Supply Chain Compromise", c_skill_pin, "pin skill versions and review updates"),
    Check("SEC-01", "Secrets not in env", 10, "ASI03", "Unsecured Credentials", c_env, "inject short-lived credentials per tool call instead"),
    Check("LOG-01", "Logging on and tamper-evident", 6, "ASI10", "Defense Evasion (log tampering)", c_logging, "write append-only, hash-chained logs outside the agent"),
    Check("MOD-01", "Model provider allowlist", 6, "ASI07", "Supply Chain Compromise (model/service)", c_models, "allow only approved model endpoints"),
    Check("GW-01", "Gateway loopback and auth", 10, "ASI03", "Valid Accounts / Initial Access", c_gateway, "bind loopback, require a token"),
]


def audit(cfg: dict) -> dict:
    results = []
    for c in CHECKS:
        ok, msg = c.fn(cfg)
        results.append({"id": c.id, "title": c.title, "passed": ok, "message": msg, "weight": c.weight, "asi": c.asi, "atlas": c.atlas, "fix": c.fix})
    total = sum(r["weight"] for r in results)
    got = sum(r["weight"] for r in results if r["passed"])
    score = round(100 * got / total)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 50 else "F"
    return {"name": cfg.get("name", "?"), "score": score, "grade": grade, "results": results,
            "failed": [r["id"] for r in results if not r["passed"]]}


def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())


def by_asi(report: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for r in report["results"]:
        if not r["passed"]:
            out.setdefault(r["asi"], []).append(r["id"])
    return out
