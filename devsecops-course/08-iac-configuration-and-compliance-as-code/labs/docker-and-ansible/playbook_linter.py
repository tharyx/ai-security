"""Playbook linter for a Docker-host Ansible playbook (teaching tool, offline, no Ansible needed).

Rules (rule ids are ours, not ansible-lint's):
  ANS-001 privilege: root-needing modules run without become
  ANS-002 secrets: tasks handling passwords/tokens without no_log: true
  ANS-003 images: docker images that are not pinned by digest (or use :latest)
  ANS-004 daemon: /etc/docker/daemon.json missing or not hardened
  ANS-005 idempotency smells: command/shell without creates/changed_when, state: latest, appends
  ANS-006 file modes and TLS: world-writable modes, validate_certs: false, plain http downloads
  ANS-007 literal secrets in vars (use Ansible Vault or an external secrets manager)
  ANS-008 remote_user: root (connect as a normal user and use become)

Real-tool twin: ansible-lint (see real-tools/ansible.md). This is NOT a replacement.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import yaml

VAULT_MARK = "<<ANSIBLE-VAULT-ENCRYPTED>>"


class _Loader(yaml.SafeLoader):
    pass


_Loader.add_constructor("!vault", lambda loader, node: VAULT_MARK)

KEYWORDS = {
    "name", "become", "become_user", "become_method", "become_flags", "when", "tags", "register", "vars",
    "no_log", "loop", "with_items", "notify", "changed_when", "failed_when", "ignore_errors", "environment",
    "delegate_to", "args", "block", "rescue", "always", "until", "retries", "delay", "check_mode", "diff",
    "listen", "run_once", "any_errors_fatal", "loop_control", "connection", "async", "poll",
}
PRIV_MODULES = {
    "apt", "yum", "dnf", "package", "service", "systemd", "copy", "template", "lineinfile", "blockinfile",
    "user", "group", "sysctl", "file", "cron", "docker_container", "docker_image", "docker_login", "get_url",
}
SECRET_KEY = re.compile(r"^(password|passwd|.*_password|.*_token|.*_secret|api_key|private_key|login_password)$", re.I)
SECRET_VAR = re.compile(r"\{\{\s*[\w.]*(password|secret|token|api_key)[\w.]*", re.I)
SHELLISH = {"command", "shell", "raw"}
HAS_MODULE_EQUIVALENT = re.compile(r"\b(apt-get|apt|yum|dnf)\s+install\b|\buseradd\b|\bsystemctl\b|\bdocker\s+run\b")
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    where: str
    message: str


def short(module: str) -> str:
    return module.split(".")[-1]


def task_module(task: dict) -> str | None:
    for key in task:
        if key not in KEYWORDS:
            return key
    return None


def params(task: dict, module_key: str) -> dict[str, Any]:
    value = task.get(module_key)
    if isinstance(value, dict):
        merged = dict(value)
    elif isinstance(value, str):
        merged = {}
        pairs = re.findall(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)", value)
        if pairs:
            merged.update({k: v.strip("'\"") for k, v in pairs})
        else:
            merged["_raw"] = value
    else:
        merged = {}
    if isinstance(task.get("args"), dict):
        merged.update(task["args"])
    return merged


def iter_tasks(tasks: list, inherited_become: Any) -> Iterator[tuple[dict, Any]]:
    for task in tasks or []:
        if not isinstance(task, dict):
            continue
        become = task.get("become", inherited_become)
        if "block" in task:
            yield from iter_tasks(task["block"], become)
            continue
        yield task, become


def resolve(text: Any, variables: dict) -> Any:
    """Resolve '{{ var }}' or '{{ var | filter }}' against play vars (very small subset)."""
    if not isinstance(text, str):
        return text
    m = re.fullmatch(r"\s*\{\{\s*(\w+)\s*(\|[^}]*)?\}\}\s*", text)
    if m and m.group(1) in variables:
        return variables[m.group(1)]
    return text


def lint_play(play: dict, play_index: int) -> list[Finding]:
    out: list[Finding] = []
    pv = play.get("vars", {}) or {}
    where_play = f"play[{play_index}]"
    if play.get("remote_user") == "root":
        out.append(Finding("ANS-008", "MEDIUM", where_play, "remote_user is root: connect as a normal user and use become"))
    for key, value in pv.items():
        if SECRET_KEY.match(key) and isinstance(value, str) and value != VAULT_MARK and "{{" not in value and value:
            out.append(Finding("ANS-007", "CRITICAL", f"{where_play}.vars.{key}", "literal secret in vars: use !vault or a secrets manager lookup"))
    tasks = list(iter_tasks(play.get("pre_tasks", []), play.get("become")))
    tasks += list(iter_tasks(play.get("tasks", []), play.get("become")))
    installs_docker = False
    daemon_task_seen = False
    for task, become in tasks:
        key = task_module(task)
        if key is None:
            continue
        mod = short(key)
        p = params(task, key)
        label = f"{where_play}:{task.get('name', mod)}"
        for k, v in (task.get("vars") or {}).items():
            if SECRET_KEY.match(k) and isinstance(v, str) and v != VAULT_MARK and "{{" not in v:
                out.append(Finding("ANS-007", "CRITICAL", label, f"literal secret in task var {k}"))
        # ANS-001
        if mod in PRIV_MODULES and not become:
            out.append(Finding("ANS-001", "HIGH", label, f"{mod} needs privileges but no become (set become: true on the task or play)"))
        # ANS-002
        secretish = any(SECRET_KEY.match(k) for k in p) or any(isinstance(v, str) and SECRET_VAR.search(v) for v in p.values())
        if secretish and task.get("no_log") is not True:
            out.append(Finding("ANS-002", "HIGH", label, "task handles a secret without no_log: true (it will print in logs and callbacks)"))
        # ANS-003
        if mod in {"docker_container", "docker_image"}:
            image = resolve(p.get("image") or p.get("name"), pv)
            if isinstance(image, str):
                if "{{" in image:
                    out.append(Finding("ANS-003", "LOW", label, "image is a template variable that could not be resolved: cannot verify pinning"))
                elif "@sha256:" in image:
                    pass
                elif image.endswith(":latest") or ":" not in image.rsplit("/", 1)[-1]:
                    out.append(Finding("ANS-003", "HIGH", label, f"image {image} is unpinned or :latest"))
                else:
                    out.append(Finding("ANS-003", "MEDIUM", label, f"image {image} uses a mutable tag: pin the digest (@sha256:...)"))
        # ANS-004 bookkeeping
        if mod in {"apt", "package", "yum", "dnf"} and "docker" in json.dumps(p.get("name", "")):
            installs_docker = True
        dest = str(p.get("dest") or p.get("path") or "")
        if dest.endswith("daemon.json"):
            daemon_task_seen = True
            out.extend(check_daemon(p, pv, label))
        # ANS-005
        if mod in SHELLISH:
            raw = str(p.get("_raw") or p.get("cmd") or task.get(key) or "")
            if not (p.get("creates") or p.get("removes") or "changed_when" in task):
                out.append(Finding("ANS-005", "MEDIUM", label, f"{mod} without creates/removes/changed_when is not idempotent"))
            if ">>" in raw:
                out.append(Finding("ANS-005", "MEDIUM", label, "appending with >> adds a line on every run: use lineinfile or the sysctl module"))
            if HAS_MODULE_EQUIVALENT.search(raw):
                out.append(Finding("ANS-005", "MEDIUM", label, "a dedicated module exists for this action (package, service, user, docker_container)"))
        if p.get("state") == "latest" and mod in {"apt", "yum", "dnf", "package"}:
            out.append(Finding("ANS-005", "LOW", label, "state: latest changes the host on every run; use present and pin versions, upgrade deliberately"))
        if mod == "lineinfile" and not p.get("regexp"):
            out.append(Finding("ANS-005", "MEDIUM", label, "lineinfile without regexp can duplicate or fail to replace lines"))
        # ANS-006
        mode = str(p.get("mode", ""))
        if mode in {"0777", "777", "0666", "666"}:
            out.append(Finding("ANS-006", "HIGH", label, f"world-writable mode {mode}"))
        if str(p.get("validate_certs")).lower() in {"false", "no"}:
            out.append(Finding("ANS-006", "MEDIUM", label, "validate_certs is false: TLS is not verified"))
        url = str(p.get("url", ""))
        if url.startswith("http://") and not p.get("checksum"):
            out.append(Finding("ANS-006", "MEDIUM", label, "plain http download without a checksum"))
    if installs_docker and not daemon_task_seen:
        out.append(Finding("ANS-004", "HIGH", where_play, "Docker is installed but no task writes a hardened /etc/docker/daemon.json"))
    return out


REQUIRED_DAEMON = {"no-new-privileges": True, "icc": False, "userland-proxy": False, "live-restore": True}


def check_daemon(p: dict, play_vars: dict, label: str) -> list[Finding]:
    out: list[Finding] = []
    content = p.get("content")
    value = resolve(content, play_vars)
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            out.append(Finding("ANS-004", "MEDIUM", label, "daemon.json content could not be parsed or resolved"))
            return out
    if not isinstance(value, dict):
        out.append(Finding("ANS-004", "MEDIUM", label, "daemon.json content is not a mapping"))
        return out
    for k, want in REQUIRED_DAEMON.items():
        if value.get(k) is not want:
            out.append(Finding("ANS-004", "MEDIUM", label, f"daemon.json should set {k}={json.dumps(want)}"))
    if not (value.get("log-driver") and (value.get("log-opts") or {}).get("max-size")):
        out.append(Finding("ANS-004", "LOW", label, "daemon.json should set log-driver and log-opts max-size (disk exhaustion)"))
    if any(str(h).startswith("tcp://") for h in value.get("hosts", [])):
        out.append(Finding("ANS-004", "CRITICAL", label, "daemon listens on tcp://: an unauthenticated Docker API is remote root"))
    if value.get("insecure-registries"):
        out.append(Finding("ANS-004", "HIGH", label, "insecure-registries allows plain http pulls (tampering)"))
    return out


def lint_text(text: str) -> list[Finding]:
    plays = yaml.load(text, Loader=_Loader) or []
    findings: list[Finding] = []
    for i, play in enumerate(plays):
        findings.extend(lint_play(play, i))
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.where))


def lint_file(path: str | Path) -> list[Finding]:
    return lint_text(Path(path).read_text(encoding="utf-8"))


def verdict(findings: list[Finding]) -> str:
    return "FAIL" if any(f.severity in {"CRITICAL", "HIGH"} for f in findings) else "PASS"


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        res = lint_file(arg)
        print(f"{arg}: {verdict(res)} ({len(res)} finding(s))")
