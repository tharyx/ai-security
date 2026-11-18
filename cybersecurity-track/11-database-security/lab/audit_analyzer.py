"""Analyze synthetic Oracle-Unified-Audit-style records (offline).

Each record is a dict whose keys follow columns of the UNIFIED_AUDIT_TRAIL view:
EVENT_TIMESTAMP, DBUSERNAME, USERHOST, CLIENT_PROGRAM_NAME, ACTION_NAME, RETURN_CODE,
OBJECT_SCHEMA, OBJECT_NAME, SQL_TEXT. RETURN_CODE 0 means success; 1017 is ORA-01017
(invalid username/password), 28000 is ORA-28000 (account locked).

Rules:
  PRIV_GRANT_OUTSIDE_WINDOW  GRANT of DBA / SYSDBA / an ANY privilege outside a change window
  MASS_SELECT                many SELECTs on sensitive tables in a short time
  NEW_HOST_OR_PROGRAM        a login from a host or client program not in the user's baseline
  AUDIT_TAMPERING            NOAUDIT, DROP/ALTER AUDIT POLICY, or audit-trail cleanup
  ADMIN_LOGIN_BURST          many failed logins on SYS/SYSTEM
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# (weekday 0=Mon, start_hour, end_hour) in the same timezone as the records.
DEFAULT_CHANGE_WINDOWS = [(1, 20, 23), (3, 20, 23)]  # Tue and Thu, 20:00-23:59
SENSITIVE_TABLES = {"CUSTOMERS", "CARD_DATA", "EMPLOYEE_SALARY"}
ADMIN_USERS = {"SYS", "SYSTEM"}

PRIV_GRANT = re.compile(
    r"^\s*GRANT\s+(?P<what>.+?)\s+TO\s+", re.IGNORECASE | re.DOTALL)
PRIVILEGED_WORDS = re.compile(r"\b(DBA|SYSDBA|SYSOPER|AUDIT_ADMIN|IMP_FULL_DATABASE|EXP_FULL_DATABASE)\b"
                              r"|\b\w+\s+ANY\s+\w+", re.IGNORECASE)
TAMPER_ACTIONS = {"NOAUDIT", "DROP AUDIT POLICY", "ALTER AUDIT POLICY"}


@dataclass
class DbFinding:
    rule: str
    severity: str
    time: str
    user: str
    detail: str


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def in_change_window(ts: datetime, windows=DEFAULT_CHANGE_WINDOWS) -> bool:
    return any(ts.weekday() == d and start <= ts.hour <= end for d, start, end in windows)


def build_baseline(records: list[dict]) -> dict[str, dict[str, set[str]]]:
    """Learn which hosts and programs each user normally logs in from."""
    base: dict[str, dict[str, set[str]]] = {}
    for r in records:
        if r["ACTION_NAME"] == "LOGON" and r["RETURN_CODE"] == 0:
            entry = base.setdefault(r["DBUSERNAME"], {"hosts": set(), "programs": set()})
            entry["hosts"].add(r["USERHOST"])
            entry["programs"].add(r["CLIENT_PROGRAM_NAME"])
    return base


def analyze(
    records: list[dict],
    baseline: dict[str, dict[str, set[str]]],
    change_windows=DEFAULT_CHANGE_WINDOWS,
    sensitive_tables: set[str] = SENSITIVE_TABLES,
    service_accounts: dict[str, set[str]] | None = None,
    select_threshold: int = 20,
    select_window: timedelta = timedelta(minutes=5),
    login_fail_threshold: int = 5,
    login_fail_window: timedelta = timedelta(minutes=10),
) -> list[DbFinding]:
    """service_accounts maps a user to the programs allowed to read sensitive tables in bulk."""
    service_accounts = service_accounts or {}
    recs = sorted(records, key=lambda r: parse_ts(r["EVENT_TIMESTAMP"]))
    findings: list[DbFinding] = []
    selects: dict[str, list[datetime]] = {}
    select_flagged: set[str] = set()
    fails: dict[str, list[datetime]] = {}
    fail_open: dict[str, bool] = {}
    new_login_seen: set[tuple[str, str, str]] = set()

    for r in recs:
        ts = parse_ts(r["EVENT_TIMESTAMP"])
        when = r["EVENT_TIMESTAMP"]
        user = r["DBUSERNAME"]
        action = r["ACTION_NAME"]
        sql = r.get("SQL_TEXT") or ""
        ok = r["RETURN_CODE"] == 0

        # 1. Privileged grant outside a change window
        if action == "GRANT" and ok:
            m = PRIV_GRANT.match(sql)
            if m and PRIVILEGED_WORDS.search(m.group("what")) and not in_change_window(ts, change_windows):
                findings.append(DbFinding(
                    "PRIV_GRANT_OUTSIDE_WINDOW", "high", when, user,
                    f"{sql.strip()} (from {r['USERHOST']}, {r['CLIENT_PROGRAM_NAME']})"))

        # 2. Mass SELECT on sensitive tables
        if (action == "SELECT" and ok and (r.get("OBJECT_NAME") or "").upper() in sensitive_tables
                and r["CLIENT_PROGRAM_NAME"] not in service_accounts.get(user, set())):
            recent = [t for t in selects.get(user, []) if ts - t <= select_window] + [ts]
            selects[user] = recent
            if len(recent) >= select_threshold and user not in select_flagged:
                select_flagged.add(user)
                findings.append(DbFinding(
                    "MASS_SELECT", "high", when, user,
                    f"{len(recent)} SELECTs on sensitive tables within {int(select_window.total_seconds() // 60)} min "
                    f"via {r['CLIENT_PROGRAM_NAME']} from {r['USERHOST']}"))

        # 3. New host or program at logon
        if action == "LOGON" and ok:
            known = baseline.get(user)
            host, prog = r["USERHOST"], r["CLIENT_PROGRAM_NAME"]
            new = []
            if known is None:
                new.append("user has no baseline")
            else:
                if host not in known["hosts"]:
                    new.append(f"new host {host}")
                if prog not in known["programs"]:
                    new.append(f"new program '{prog}'")
            key = (user, host, prog)
            if new and key not in new_login_seen:
                new_login_seen.add(key)
                findings.append(DbFinding("NEW_HOST_OR_PROGRAM", "medium", when, user, "; ".join(new)))

        # 4. Audit tampering
        if action in TAMPER_ACTIONS or re.search(r"\bNOAUDIT\b", sql, re.IGNORECASE):
            findings.append(DbFinding("AUDIT_TAMPERING", "critical", when, user,
                                      f"{sql.strip() or action} (from {r['USERHOST']})"))
        elif "CLEAN_AUDIT_TRAIL" in sql.upper() or "DBMS_AUDIT_MGMT" in sql.upper():
            findings.append(DbFinding("AUDIT_TAMPERING", "medium", when, user,
                                      f"Audit trail management call: {sql.strip()}"))

        # 5. Failed-login burst on SYS/SYSTEM
        if action == "LOGON" and user in ADMIN_USERS:
            if not ok:
                recent = [t for t in fails.get(user, []) if ts - t <= login_fail_window] + [ts]
                fails[user] = recent
                if len(recent) >= login_fail_threshold and not fail_open.get(user):
                    fail_open[user] = True
                    findings.append(DbFinding(
                        "ADMIN_LOGIN_BURST", "high", when, user,
                        f"{len(recent)} failed logins within {int(login_fail_window.total_seconds() // 60)} min "
                        f"(latest from {r['USERHOST']})"))
            elif fail_open.get(user):
                findings.append(DbFinding(
                    "ADMIN_LOGIN_BURST", "critical", when, user,
                    f"Successful {user} login right after a failure burst (from {r['USERHOST']})"))
                fail_open[user] = False
                fails[user] = []

    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.time))
