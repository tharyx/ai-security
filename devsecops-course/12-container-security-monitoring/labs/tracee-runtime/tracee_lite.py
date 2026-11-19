"""Tracee-style signature detection over an eBPF-event fixture (not Tracee itself).

Tracee (Aqua Security) collects kernel events with eBPF and runs signatures over the
stream. Event/arg names below follow its style (sched_process_exec, security_file_open,
ptrace, mount ...) but are simplified: verify against the Tracee docs for your version.
Signature ids are this lab's own (DSO-TRC-xxx).
"""
from __future__ import annotations

TEMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")


def arg(ev: dict, name: str, default=None):
    for a in ev.get("args", []):
        if a["name"] == name:
            return a["value"]
    return default


def in_container(ev: dict) -> bool:
    return bool(ev.get("containerId"))


class Dropped:
    """Executable written to a temp dir, then executed: the classic 'download and run'."""
    meta = {"id": "DSO-TRC-001", "name": "Dropped executable", "severity": 3}

    def __init__(self):
        self.written: set[str] = set()

    def on_event(self, ev):
        if ev["eventName"] == "security_file_open" and arg(ev, "flags", "") in ("O_WRONLY", "O_RDWR", "O_CREAT|O_WRONLY"):
            p = arg(ev, "pathname", "")
            if p.startswith(TEMP_DIRS):
                self.written.add(p)
        elif ev["eventName"] == "sched_process_exec":
            p = arg(ev, "pathname", "")
            if p in self.written:
                return f"{ev['processName']} executed {p} which was written earlier in a temp dir"


class AntiDebug:
    """ptrace(PTRACE_TRACEME) makes a process refuse to be debugged: common in malware."""
    meta = {"id": "DSO-TRC-002", "name": "Anti-debugging", "severity": 2}

    def on_event(self, ev):
        if ev["eventName"] == "ptrace" and arg(ev, "request") == "PTRACE_TRACEME":
            return f"{ev['processName']} called PTRACE_TRACEME"


class ContainerEscape:
    meta = {"id": "DSO-TRC-003", "name": "Container escape attempt", "severity": 3}

    def on_event(self, ev):
        if not in_container(ev):
            return None
        name = ev["eventName"]
        if name == "security_file_open" and arg(ev, "pathname", "").endswith(("release_agent", "notify_on_release")):
            return "write to cgroup release_agent (classic privileged-container escape)"
        if name == "mount" and str(arg(ev, "dev_name", "")).startswith("/dev/sd"):
            return f"container mounted host block device {arg(ev, 'dev_name')}"
        if name == "sched_process_exec" and arg(ev, "pathname", "").endswith("nsenter") and \
                any(x in ("-t", "--target") for x in arg(ev, "argv", [])) and "1" in arg(ev, "argv", []):
            return "nsenter targeting PID 1 (host namespaces)"
        return None


def default_signatures():
    return [Dropped(), AntiDebug(), ContainerEscape()]


def run(events: list[dict], sigs=None) -> list[dict]:
    sigs = sigs or default_signatures()
    out = []
    for ev in events:
        for s in sigs:
            msg = s.on_event(ev)
            if msg:
                out.append({**s.meta, "container": ev.get("containerId", "host"), "ts": ev["timestamp"], "msg": msg})
    return out
