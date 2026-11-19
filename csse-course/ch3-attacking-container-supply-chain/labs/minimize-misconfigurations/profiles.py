"""Validate the example seccomp and AppArmor profiles that ship with this lab (text/JSON checks only)."""
from __future__ import annotations

import json
import re
from pathlib import Path

# Syscalls that give a container the tools to attack the kernel or leave its namespaces.
RISKY_SYSCALLS = {"mount", "umount2", "ptrace", "unshare", "setns", "bpf", "keyctl", "kexec_load", "init_module",
                  "finit_module", "delete_module", "open_by_handle_at", "reboot", "swapon", "pivot_root", "process_vm_writev",
                  "userfaultfd", "perf_event_open", "personality", "iopl", "ioperm"}


def validate_seccomp(profile: dict) -> list[str]:
    problems = []
    if profile.get("defaultAction") not in ("SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_TRAP"):
        problems.append("defaultAction must deny by default (ERRNO or KILL), otherwise the profile is an allowlist in name only")
    allowed: set[str] = set()
    for rule in profile.get("syscalls", []):
        if rule.get("action") == "SCMP_ACT_ALLOW":
            allowed |= set(rule.get("names", []))
    risky = sorted(allowed & RISKY_SYSCALLS)
    if risky:
        problems.append(f"allows risky syscalls: {risky}")
    if not allowed:
        problems.append("no syscalls are allowed; the container could not even start")
    return problems


def validate_apparmor(text: str) -> list[str]:
    problems = []
    if not re.search(r"^profile\s+\S+\s+flags=\(attach_disconnected", text, re.M) and not re.search(r"^profile\s+\S+", text, re.M):
        problems.append("no 'profile <name>' header")
    header = re.search(r"^profile\s+\S+\s+flags=\(([^)]*)\)", text, re.M)
    if header and "complain" in header.group(1):
        problems.append("profile is in complain mode: it logs but does not block")
    for needed in ("deny mount", "deny /proc/sys/", "deny /sys/", "deny ptrace", "deny network raw"):
        if needed not in text:
            problems.append(f"missing rule: {needed}")
    if re.search(r"^\s*/\*\*\s+rwx", text, re.M):
        problems.append("allows rwx on everything")
    return problems


def load_seccomp(path: Path) -> dict:
    return json.loads(Path(path).read_text())
