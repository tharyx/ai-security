"""Detect risky activity in CloudTrail-style JSON events (offline, synthetic data).

Input: a list of event dicts shaped like AWS CloudTrail records (the "Records" list
of a log file). Output: a list of Finding objects. No AWS calls are made.

Rules:
  ROOT_LOGIN             the root user signed in to the console
  KEY_NEW_COUNTRY        a freshly created access key is used from a new country
  LOGGING_DISABLED       StopLogging / DeleteTrail
  BUCKET_MADE_PUBLIC     PutBucketPolicy with an unrestricted public Allow
  CONSOLE_LOGIN_BURST    many failed ConsoleLogin events in a short time
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

# Offline stand-in for a GeoIP database. Documentation-range IPs only.
GEO_TABLE = {
    "192.0.2.": "CA",
    "198.51.100.": "CA",
    "203.0.113.": "RU",
}

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    time: str
    actor: str
    detail: str
    mitre: str = ""


def country_of(ip: str, geo: dict[str, str] | None = None) -> str:
    for prefix, country in (geo or GEO_TABLE).items():
        if ip.startswith(prefix):
            return country
    return "??"


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_events(path: str | Path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data["Records"] if isinstance(data, dict) else data


def actor_of(event: dict) -> str:
    ident = event.get("userIdentity", {})
    return ident.get("userName") or ident.get("arn") or ident.get("type", "unknown")


def _statements(policy: dict) -> list[dict]:
    stmts = policy.get("Statement", [])
    return [stmts] if isinstance(stmts, dict) else list(stmts)


def policy_is_public(policy: dict) -> bool:
    """True if any Allow statement has a wildcard principal and no Condition."""
    for stmt in _statements(policy):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        wildcard = principal == "*" or (
            isinstance(principal, dict) and principal.get("AWS") in ("*", ["*"])
        )
        if wildcard and not stmt.get("Condition"):
            return True
    return False


def detect(
    events: list[dict],
    geo: dict[str, str] | None = None,
    burst_threshold: int = 5,
    burst_window: timedelta = timedelta(minutes=10),
) -> list[Finding]:
    events = sorted(events, key=lambda e: parse_time(e["eventTime"]))
    findings: list[Finding] = []
    seen_countries: dict[str, set[str]] = {}  # user -> countries seen on older keys
    new_keys: dict[str, str] = {}  # new access key id -> user it belongs to
    failures: dict[str, list[datetime]] = {}  # user -> recent failure times
    burst_open: dict[str, bool] = {}

    for ev in events:
        name = ev.get("eventName", "")
        when = ev["eventTime"]
        actor = actor_of(ev)
        ip = ev.get("sourceIPAddress", "")
        country = country_of(ip, geo)
        ident = ev.get("userIdentity", {})
        key_id = ident.get("accessKeyId", "")
        login = (ev.get("responseElements") or {}).get("ConsoleLogin")

        # 1. Root login
        if name == "ConsoleLogin" and ident.get("type") == "Root" and login == "Success":
            mfa = (ev.get("additionalEventData") or {}).get("MFAUsed") == "Yes"
            findings.append(Finding(
                "ROOT_LOGIN", "high" if mfa else "critical", when, "root",
                f"Root console login from {ip} ({country}), MFA {'used' if mfa else 'NOT used'}",
                "T1078.004"))

        # 2. Access key created, then used from a country never seen for that user
        if name == "CreateAccessKey" and not ev.get("errorCode"):
            target = (ev.get("requestParameters") or {}).get("userName", actor)
            new_id = ((ev.get("responseElements") or {}).get("accessKey") or {}).get("accessKeyId")
            if new_id:
                new_keys[new_id] = target
        if key_id in new_keys:
            user = new_keys[key_id]
            if country not in seen_countries.get(user, set()):
                known = sorted(seen_countries.get(user, set())) or "unknown"
                findings.append(Finding(
                    "KEY_NEW_COUNTRY", "high", when, user,
                    f"New access key {key_id} used from {ip} ({country}); user normally works from {known}",
                    "T1078.004"))
                seen_countries.setdefault(user, set()).add(country)  # alert once per country
        elif actor != "unknown" and country != "??":
            seen_countries.setdefault(actor, set()).add(country)

        # 3. Logging disabled
        if name in ("StopLogging", "DeleteTrail") and not ev.get("errorCode"):
            trail = (ev.get("requestParameters") or {}).get("name", "unknown trail")
            findings.append(Finding(
                "LOGGING_DISABLED", "critical", when, actor,
                f"{name} on trail '{trail}' from {ip}", "T1562.008"))

        # 4. Bucket policy that makes a bucket public
        if name == "PutBucketPolicy" and not ev.get("errorCode"):
            params = ev.get("requestParameters") or {}
            if policy_is_public(params.get("bucketPolicy") or {}):
                findings.append(Finding(
                    "BUCKET_MADE_PUBLIC", "high", when, actor,
                    f"PutBucketPolicy on '{params.get('bucketName')}' allows Principal * with no condition",
                    "T1530"))

        # 5. Burst of failed console logins (per user name)
        if name == "ConsoleLogin" and login == "Failure":
            user = ident.get("userName") or (ev.get("requestParameters") or {}).get("userName", "unknown")
            t = parse_time(when)
            recent = [x for x in failures.get(user, []) if t - x <= burst_window] + [t]
            failures[user] = recent
            if len(recent) >= burst_threshold and not burst_open.get(user):
                burst_open[user] = True
                findings.append(Finding(
                    "CONSOLE_LOGIN_BURST", "medium", when, user,
                    f"{len(recent)} failed console logins within {int(burst_window.total_seconds() // 60)} min "
                    f"(latest source {ip})", "T1110"))
        elif name == "ConsoleLogin" and login == "Success":
            user = ident.get("userName", "")
            if burst_open.get(user):
                findings.append(Finding(
                    "CONSOLE_LOGIN_BURST", "critical", when, user,
                    f"Successful login right after a failure burst (source {ip}): possible guessed password",
                    "T1110"))
                burst_open[user] = False
                failures[user] = []

    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.time))
