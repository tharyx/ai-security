"""Parse Windows event JSON and Linux auth.log, then raise findings.

Three detections (the same ideas a SIEM rule uses):
  1. failed-login bursts (and "success right after a burst")
  2. new user accounts
  3. new services (Windows 7045) that point at risky paths
Plus a bonus: encoded PowerShell in process-creation events (4688).

Standard library only. Pure functions so they are easy to test.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

__all__ = ["Event", "Finding", "parse_windows_events", "parse_auth_log",
           "failed_login_bursts", "new_users", "new_services", "encoded_powershell", "analyze"]


@dataclass(frozen=True)
class Event:
    time: datetime
    host: str
    kind: str          # login_failed, login_ok, user_created, service_installed, process_created
    user: str = ""
    source_ip: str = ""
    detail: str = ""
    os: str = ""       # "windows" or "linux"


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str      # low, medium, high, critical
    host: str
    summary: str
    time: datetime


# ---------------------------------------------------------------- parsing

_WIN_KIND = {4624: "login_ok", 4625: "login_failed", 4720: "user_created",
             7045: "service_installed", 4688: "process_created"}


def _parse_iso(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


def parse_windows_events(data: str | list[dict]) -> list[Event]:
    """Accept a JSON string or an already-loaded list. Unknown event IDs are ignored."""
    records = json.loads(data) if isinstance(data, str) else data
    events: list[Event] = []
    for rec in records:
        kind = _WIN_KIND.get(int(rec.get("EventID", 0)))
        if kind is None:
            continue
        d = rec.get("EventData", {})
        if kind in ("login_ok", "login_failed"):
            user, ip, detail = d.get("TargetUserName", ""), d.get("IpAddress", ""), f"logon_type={d.get('LogonType', '?')}"
        elif kind == "user_created":
            user, ip, detail = d.get("TargetUserName", ""), "", f"created_by={d.get('SubjectUserName', '?')}"
        elif kind == "service_installed":
            user, ip, detail = d.get("AccountName", ""), "", f"{d.get('ServiceName', '?')} -> {d.get('ImagePath', '?')}"
        else:  # process_created
            user, ip, detail = d.get("SubjectUserName", ""), "", d.get("CommandLine", d.get("NewProcessName", ""))
        events.append(Event(_parse_iso(rec["TimeCreated"]), rec.get("Computer", "?"), kind,
                            user, ip, detail, "windows"))
    return sorted(events, key=lambda e: e.time)


_SYSLOG = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<hms>[\d:]{8})\s+(?P<host>\S+)\s+"
                     r"(?P<proc>[^:\[\s]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
_FAILED = re.compile(r"Failed \w+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+")
_ACCEPTED = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>\S+) port \d+")
_USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")


def parse_auth_log(text: str, year: int = 2026) -> list[Event]:
    """Parse Debian-style auth.log. Syslog lines have no year, so the caller supplies one."""
    events: list[Event] = []
    for line in text.splitlines():
        m = _SYSLOG.match(line.strip())
        if not m:
            continue
        when = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['hms']}",
                                 "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        msg, host = m["msg"], m["host"]
        if m["proc"] == "sshd":
            if (f := _FAILED.search(msg)):
                events.append(Event(when, host, "login_failed", f["user"], f["ip"], "ssh", "linux"))
            elif (a := _ACCEPTED.search(msg)):
                events.append(Event(when, host, "login_ok", a["user"], a["ip"], "ssh", "linux"))
        elif m["proc"] == "useradd" and (u := _USERADD.search(msg)):
            events.append(Event(when, host, "user_created", u["user"], "", "useradd", "linux"))
    return sorted(events, key=lambda e: e.time)


# ---------------------------------------------------------------- detections

def failed_login_bursts(events: list[Event], threshold: int = 5, window_seconds: int = 60) -> list[Finding]:
    """Flag a source IP with >= threshold failures inside window_seconds.

    If the same IP then logs in successfully, raise a critical finding: that is the
    classic "brute force worked" pattern.
    """
    by_ip: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.kind in ("login_failed", "login_ok") and e.source_ip:
            by_ip[(e.host, e.source_ip)].append(e)
    findings: list[Finding] = []
    window = timedelta(seconds=window_seconds)
    for (host, ip), evs in by_ip.items():
        fails = [e for e in evs if e.kind == "login_failed"]
        best: list[Event] = []
        start = 0
        for end in range(len(fails)):
            while fails[end].time - fails[start].time > window:
                start += 1
            if end - start + 1 > len(best):
                best = fails[start:end + 1]
        if len(best) < threshold:
            continue
        users = sorted({e.user for e in best})
        findings.append(Finding("failed_login_burst", "high", host,
                                f"{len(best)} failed logins from {ip} in {window_seconds}s "
                                f"(users tried: {', '.join(users)})", best[-1].time))
        later_ok = [e for e in evs if e.kind == "login_ok" and e.time >= best[-1].time
                    and e.time - best[-1].time <= window]
        if later_ok:
            findings.append(Finding("success_after_burst", "critical", host,
                                    f"{ip} logged in as '{later_ok[0].user}' right after the burst: assume compromise",
                                    later_ok[0].time))
    return sorted(findings, key=lambda f: f.time)


def new_users(events: list[Event]) -> list[Finding]:
    return [Finding("new_user", "medium", e.host, f"account '{e.user}' created ({e.detail})", e.time)
            for e in events if e.kind == "user_created"]


_RISKY_PATH = re.compile(r"(\\users\\|\\temp\\|\\appdata\\|\\programdata\\|/tmp/|cmd\.exe|powershell)", re.I)


def new_services(events: list[Event]) -> list[Finding]:
    """Event 7045: every new service is worth a look; risky image paths are 'high'."""
    out = []
    for e in events:
        if e.kind != "service_installed":
            continue
        risky = bool(_RISKY_PATH.search(e.detail))
        out.append(Finding("new_service", "high" if risky else "low", e.host,
                           f"service installed: {e.detail}" + (" [risky path]" if risky else ""), e.time))
    return out


def encoded_powershell(events: list[Event]) -> list[Finding]:
    return [Finding("encoded_powershell", "high", e.host,
                    f"PowerShell with encoded command by {e.user}", e.time)
            for e in events if e.kind == "process_created"
            and re.search(r"powershell.*\s-(e|enc|encodedcommand)\s", e.detail, re.I)]


def analyze(events: list[Event]) -> list[Finding]:
    found = (failed_login_bursts(events) + new_users(events)
             + new_services(events) + encoded_powershell(events))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(found, key=lambda f: (order[f.severity], f.time))
