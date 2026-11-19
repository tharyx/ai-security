"""Generate and validate a custom seccomp profile and AppArmor profile from observations.

Seccomp: allowlist built from an observed syscall list (an strace -f -c style capture).
AppArmor: built from observed file accesses. Both are STARTING POINTS: run your test suite
in complain mode / with an audit-only seccomp action first. Verify field names against the
Docker docs for your version.
"""
from __future__ import annotations

import re

# Needed so the container runtime itself can start the process (runc stage). Trimmed list.
RUNTIME_BASELINE = {"execve", "exit", "exit_group", "brk", "mmap", "munmap", "mprotect", "rt_sigaction",
                    "rt_sigprocmask", "rt_sigreturn", "futex", "arch_prctl", "set_tid_address", "set_robust_list",
                    "prlimit64", "getpid", "gettid", "close", "read", "write", "openat", "fstat", "newfstatat"}

DANGEROUS = {"ptrace", "mount", "umount2", "unshare", "setns", "bpf", "kexec_load", "init_module",
             "finit_module", "delete_module", "keyctl", "reboot", "swapon", "pivot_root",
             "open_by_handle_at", "perf_event_open", "userfaultfd", "process_vm_writev", "personality"}

_LINE = re.compile(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?([a-z_][a-z0-9_]*)\(")


def parse_strace(text: str) -> list[str]:
    """Unique syscall names in first-seen order from raw strace lines."""
    seen: dict[str, None] = {}
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if m:
            seen.setdefault(m.group(1))
    return list(seen)


def gen_seccomp(observed: list[str], with_baseline: bool = True) -> tuple[dict, list[str]]:
    """Return (profile, refused). Dangerous syscalls are never auto-allowed."""
    names = set(observed) | (RUNTIME_BASELINE if with_baseline else set())
    refused = sorted(names & DANGEROUS)
    allowed = sorted(names - DANGEROUS)
    profile = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,
        "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
        "syscalls": [{"names": allowed, "action": "SCMP_ACT_ALLOW"}],
    }
    return profile, refused


def validate_seccomp(profile: dict) -> list[str]:
    problems = []
    if profile.get("defaultAction") in ("SCMP_ACT_ALLOW", None):
        problems.append("defaultAction allows everything: this is a denylist, not an allowlist")
    allowed = set()
    for rule in profile.get("syscalls", []):
        if rule.get("action") == "SCMP_ACT_ALLOW":
            allowed |= set(rule.get("names", []))
    for s in sorted(allowed & DANGEROUS):
        problems.append(f"dangerous syscall allowed: {s}")
    if not allowed and profile.get("defaultAction") != "SCMP_ACT_ALLOW":
        problems.append("nothing allowed: the container cannot even start")
    return problems


def parse_accesses(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            path, mode = line.rsplit(None, 1)
            out.append((path, mode))
    return out


def gen_apparmor(name: str, accesses: list[tuple[str, str]], network: tuple[str, ...] = ("inet tcp",)) -> str:
    lines = ["#include <tunables/global>", "", f"profile {name} flags=(attach_disconnected,mediate_deleted) {{",
             "  #include <abstractions/base>", ""]
    lines += [f"  network {n}," for n in network]
    lines.append("")
    lines += [f"  {p} {m}," for p, m in accesses]
    lines += ["", "  # explicit denies: belt and braces for what the container must never touch",
              "  deny /proc/sys/** wklx,", "  deny /sys/** wklx,", "  deny /var/run/docker.sock rwklx,",
              "  deny mount,", "  deny ptrace,", "  deny capability sys_admin,", "}"]
    return "\n".join(lines) + "\n"


def validate_apparmor(text: str) -> list[str]:
    problems = []
    if not re.search(r"^profile\s+\S+", text, re.M):
        problems.append("no 'profile <name>' header")
    if text.count("{") != text.count("}"):
        problems.append("unbalanced braces")
    if re.search(r"flags=\([^)]*complain", text):
        problems.append("profile is in complain mode: it logs but does not enforce")
    for ln in text.splitlines():
        s = ln.strip().rstrip(",")
        if s.startswith("deny") or s.startswith("#"):
            continue
        if re.fullmatch(r"file", s):
            problems.append("blanket 'file' rule allows all file access")
        if re.fullmatch(r"/\*\*\s+r?w[a-z]*", s) or re.fullmatch(r"/\*\*\s+rwx", s):
            problems.append(f"root-wide write rule: {s}")
        if re.fullmatch(r"capability\s+(sys_admin|sys_ptrace|sys_module)", s):
            problems.append(f"dangerous capability allowed: {s}")
        if re.fullmatch(r"ptrace", s) or s.startswith("ptrace ") or s == "mount":
            problems.append(f"allows {s}")
        if "docker.sock" in s:
            problems.append("allows access to docker.sock")
    if not re.search(r"deny\s+/proc/sys", text):
        problems.append("missing deny for /proc/sys")
    return problems
