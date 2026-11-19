"""Apply a (fixture) Ansible hardening role to a FAKE host state, then verify with CIS-like checks.

Teaching simulator, not Ansible: it understands only the handful of modules used by the role
(package, lineinfile, sysctl, copy, service, user, file), loops, and a tiny '{{ }}' renderer.
Every module is idempotent: it reports changed=True only when the state really changes, which
is exactly the property you test on a real role with `ansible-playbook --check` or Molecule.

The checks are "CIS-like": they mirror the idea of CIS Benchmark controls, not the licensed text.
Real-tool twin: ansible-playbook + InSpec/OpenSCAP (see real-tools/).
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

EXPR = re.compile(r"\{\{\s*([^{}]*?)\s*\}\}", re.S)


# ---------------------------------------------------------------- tiny template renderer
def lookup(path: str, ctx: dict) -> Any:
    cur: Any = ctx
    for part in path.split("."):
        cur = cur[part]
    return cur


def eval_expr(expr: str, ctx: dict) -> Any:
    parts = [p.strip() for p in re.split(r"\|(?![^()]*\))", expr)]
    value = lookup(parts[0], ctx)
    for flt in parts[1:]:
        m = re.fullmatch(r"join\((['\"])(.*)\1\)", flt, re.S)
        if not m:
            raise ValueError(f"unsupported filter: {flt}")
        value = m.group(2).join(str(v) for v in value)
    return value


def render(value: Any, ctx: dict) -> Any:
    if isinstance(value, str):
        full = EXPR.fullmatch(value)
        if full:
            return eval_expr(full.group(1), ctx)
        return EXPR.sub(lambda m: str(eval_expr(m.group(1), ctx)), value)
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    return value


# ---------------------------------------------------------------- modules (each returns changed?)
def mod_package(state: dict, p: dict) -> bool:
    pkgs = state.setdefault("packages", {})
    name = p["name"]
    if p["state"] == "present":
        if name in pkgs:
            return False
        pkgs[name] = "latest-in-repo"
        return True
    return pkgs.pop(name, None) is not None


def mod_lineinfile(state: dict, p: dict) -> bool:
    f = state.setdefault("files", {}).setdefault(p["path"], {"content": "", "mode": "0644", "owner": "root"})
    lines = f["content"].split("\n") if f["content"] else []
    rx = re.compile(p["regexp"])
    last = max((i for i, ln in enumerate(lines) if rx.search(ln)), default=None)
    if last is None:
        lines.append(p["line"])
    elif lines[last] == p["line"]:
        return False
    else:
        lines[last] = p["line"]  # real lineinfile replaces the LAST match
    f["content"] = "\n".join(lines)
    return True


def mod_sysctl(state: dict, p: dict) -> bool:
    table = state.setdefault("sysctl", {})
    if table.get(p["name"]) == str(p["value"]):
        return False
    table[p["name"]] = str(p["value"])
    return True


def mod_copy(state: dict, p: dict) -> bool:
    files = state.setdefault("files", {})
    new = {"content": p["content"], "mode": p.get("mode", "0644"), "owner": p.get("owner", "root")}
    if files.get(p["dest"]) == new:
        return False
    files[p["dest"]] = new
    return True


def mod_service(state: dict, p: dict) -> bool:
    svc = state.setdefault("services", {}).setdefault(p["name"], {"enabled": False, "running": False})
    want = {"enabled": p.get("enabled", svc["enabled"]), "running": p.get("state") in {"started", "restarted"} or svc["running"]}
    if svc == want:
        return False
    svc.update(want)
    return True


def mod_user(state: dict, p: dict) -> bool:
    users = state.setdefault("users", {})
    name = p["name"]
    if p.get("state") == "absent":
        return users.pop(name, None) is not None
    if name not in users:
        users[name] = {"uid": 1500, "shell": p.get("shell", "/bin/bash")}
        return True
    if "shell" in p and users[name].get("shell") != p["shell"]:
        users[name]["shell"] = p["shell"]
        return True
    return False


def mod_file(state: dict, p: dict) -> bool:
    f = state.setdefault("files", {}).setdefault(p["path"], {"content": "", "mode": "0644", "owner": "root"})
    changed = False
    for key in ("mode", "owner"):
        if key in p and f.get(key) != p[key]:
            f[key] = p[key]
            changed = True
    return changed


MODULES: dict[str, Callable[[dict, dict], bool]] = {
    "package": mod_package, "lineinfile": mod_lineinfile, "sysctl": mod_sysctl, "copy": mod_copy,
    "service": mod_service, "user": mod_user, "file": mod_file,
}


@dataclass
class ApplyReport:
    changes: list[str] = field(default_factory=list)
    ok: int = 0

    @property
    def changed(self) -> int:
        return len(self.changes)


def load_role(role_dir: str | Path) -> tuple[list[dict], dict]:
    role = Path(role_dir)
    tasks = yaml.safe_load((role / "tasks" / "main.yml").read_text(encoding="utf-8"))
    defaults = yaml.safe_load((role / "defaults" / "main.yml").read_text(encoding="utf-8"))
    return tasks, defaults


def apply_role(state: dict, role_dir: str | Path, overrides: dict | None = None) -> ApplyReport:
    tasks, defaults = load_role(role_dir)
    variables = {**defaults, **(overrides or {})}
    report = ApplyReport()
    for task in tasks:
        module_key = next(k for k in task if k not in {"name", "loop", "become", "when", "tags"})
        module = module_key.split(".")[-1]
        items = render(task["loop"], variables) if "loop" in task else [None]
        for item in items:
            ctx = {**variables, "item": item}
            params = render(task[module_key], ctx)
            if MODULES[module](state, params):
                report.changes.append(f"{task['name']} [{item if not isinstance(item, dict) else item.get('key')}]" if item is not None else task["name"])
            else:
                report.ok += 1
    return report


# ---------------------------------------------------------------- CIS-like checks
def sshd_value(state: dict, key: str) -> str | None:
    """First uncommented occurrence wins in sshd_config."""
    content = state.get("files", {}).get("/etc/ssh/sshd_config", {}).get("content", "")
    for line in content.split("\n"):
        s = line.strip()
        if s and not s.startswith("#") and s.split(None, 1)[0].lower() == key.lower():
            parts = s.split(None, 1)
            return parts[1] if len(parts) > 1 else ""
    return None


def mode_ok(actual: str | None, strictest_allowed: str) -> bool:
    if actual is None:
        return False
    return (int(actual, 8) & ~int(strictest_allowed, 8)) == 0


@dataclass(frozen=True)
class Check:
    check_id: str
    title: str
    severity: str
    fn: Callable[[dict], bool]


def _installed(s: dict, n: str) -> bool:
    return n in s.get("packages", {})


def _audit_rules(s: dict) -> str:
    return s.get("files", {}).get("/etc/audit/rules.d/hardening.rules", {}).get("content", "")


CHECKS: list[Check] = [
    Check("CIS-SSH-01", "sshd: PermitRootLogin is no", "HIGH", lambda s: sshd_value(s, "PermitRootLogin") == "no"),
    Check("CIS-SSH-02", "sshd: PasswordAuthentication is no", "HIGH", lambda s: sshd_value(s, "PasswordAuthentication") == "no"),
    Check("CIS-SSH-03", "sshd: MaxAuthTries is 4 or less", "MEDIUM", lambda s: (sshd_value(s, "MaxAuthTries") or "99").isdigit() and int(sshd_value(s, "MaxAuthTries") or 99) <= 4),
    Check("CIS-SSH-04", "sshd: X11Forwarding is no", "LOW", lambda s: sshd_value(s, "X11Forwarding") == "no"),
    Check("CIS-SSH-05", "sshd: ClientAliveInterval between 1 and 900", "LOW", lambda s: (sshd_value(s, "ClientAliveInterval") or "0").isdigit() and 1 <= int(sshd_value(s, "ClientAliveInterval") or 0) <= 900),
    Check("CIS-PKG-01", "no telnet client or rsh server installed", "HIGH", lambda s: not any(_installed(s, n) for n in ("telnet", "rsh-server", "talk"))),
    Check("CIS-PKG-02", "auditd and chrony installed", "MEDIUM", lambda s: _installed(s, "auditd") and _installed(s, "chrony")),
    Check("CIS-AUD-01", "auditd enabled and running", "MEDIUM", lambda s: s.get("services", {}).get("auditd") == {"enabled": True, "running": True}),
    Check("CIS-AUD-02", "audit watches on passwd, shadow and sudoers", "MEDIUM", lambda s: all(w in _audit_rules(s) for w in ("/etc/passwd", "/etc/shadow", "/etc/sudoers"))),
    Check("CIS-SYS-01", "net.ipv4.ip_forward is 0", "MEDIUM", lambda s: s.get("sysctl", {}).get("net.ipv4.ip_forward") == "0"),
    Check("CIS-SYS-02", "ICMP redirects not accepted", "MEDIUM", lambda s: s.get("sysctl", {}).get("net.ipv4.conf.all.accept_redirects") == "0"),
    Check("CIS-SYS-03", "ASLR fully enabled (randomize_va_space = 2)", "MEDIUM", lambda s: s.get("sysctl", {}).get("kernel.randomize_va_space") == "2"),
    Check("CIS-SYS-04", "TCP SYN cookies enabled", "LOW", lambda s: s.get("sysctl", {}).get("net.ipv4.tcp_syncookies") == "1"),
    Check("CIS-USR-01", "no guest account", "MEDIUM", lambda s: "guest" not in s.get("users", {})),
    Check("CIS-USR-02", "root is the only UID 0 account", "CRITICAL", lambda s: [n for n, u in s.get("users", {}).items() if u.get("uid") == 0] == ["root"]),
    Check("CIS-USR-03", "service accounts use a nologin shell", "MEDIUM", lambda s: all(s.get("users", {}).get(n, {}).get("shell", "").endswith("nologin") for n in ("appsvc", "backup") if n in s.get("users", {}))),
    Check("CIS-FS-01", "/etc/shadow mode 0640 or stricter", "HIGH", lambda s: mode_ok(s.get("files", {}).get("/etc/shadow", {}).get("mode"), "0640")),
    Check("CIS-FS-02", "/etc/passwd mode 0644 or stricter", "MEDIUM", lambda s: mode_ok(s.get("files", {}).get("/etc/passwd", {}).get("mode"), "0644")),
]


def run_checks(state: dict) -> list[dict]:
    out = []
    for c in CHECKS:
        try:
            ok = bool(c.fn(state))
        except Exception:  # a missing key is a failed control, not a crash
            ok = False
        out.append({"id": c.check_id, "title": c.title, "severity": c.severity, "status": "pass" if ok else "fail"})
    return out


def score(results: list[dict]) -> float:
    return round(100.0 * sum(r["status"] == "pass" for r in results) / len(results), 1)


def load_state(path: str | Path) -> dict:
    return copy.deepcopy(json.loads(Path(path).read_text(encoding="utf-8")))
