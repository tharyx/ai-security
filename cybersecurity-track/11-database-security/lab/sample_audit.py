"""Synthetic Oracle-Unified-Audit-style records. All hosts and users are fake (*.example, 192.0.2.x).

baseline_records(): a normal week for the learning period.
incident_records(): one bad night, mixed with a legal change-window GRANT and normal app traffic.
"""

from __future__ import annotations

from datetime import datetime, timedelta

APP_PROGRAM = "JDBC Thin Client"
APP_HOST = "app01.example"
DBA_HOST = "dba-ws01.example"


def _rec(ts, user, action, host, program, rc=0, obj=None, sql=None, schema=None):
    return {
        "EVENT_TIMESTAMP": ts.strftime("%Y-%m-%d %H:%M:%S"), "DBUSERNAME": user, "ACTION_NAME": action,
        "USERHOST": host, "CLIENT_PROGRAM_NAME": program, "RETURN_CODE": rc,
        "OBJECT_SCHEMA": schema or ("APP" if obj else None), "OBJECT_NAME": obj, "SQL_TEXT": sql,
        "OS_USERNAME": "oracle" if user in ("SYS", "SYSTEM") else "appsvc",
    }


def baseline_records() -> list[dict]:
    t = datetime(2026, 3, 2, 9, 0, 0)  # a Monday
    out = [
        _rec(t, "APP_USER", "LOGON", APP_HOST, APP_PROGRAM),
        _rec(t + timedelta(minutes=1), "DBA_ALICE", "LOGON", DBA_HOST, "sqlplus@dba-ws01.example (TNS V1-V3)"),
        _rec(t + timedelta(minutes=2), "DBA_ALICE", "LOGON", DBA_HOST, "SQL Developer"),
        _rec(t + timedelta(minutes=3), "SYS", "LOGON", "dbhost01.example", "sqlplus@dbhost01.example (TNS V1-V3)"),
        _rec(t + timedelta(minutes=4), "BATCH_ETL", "LOGON", "etl01.example", "python3"),
    ]
    for i in range(30):  # the app reads CUSTOMERS all day: normal
        out.append(_rec(t + timedelta(minutes=10, seconds=10 * i), "APP_USER", "SELECT", APP_HOST, APP_PROGRAM,
                        obj="CUSTOMERS", sql="SELECT * FROM app.customers WHERE id = :1"))
    return out


def incident_records() -> list[dict]:
    tue = datetime(2026, 3, 10, 21, 0, 0)   # Tuesday 21:00: inside the change window
    wed = datetime(2026, 3, 11, 2, 0, 0)    # Wednesday 02:00: outside any window
    out = [
        # Normal traffic (must not alert)
        _rec(tue - timedelta(hours=12), "APP_USER", "LOGON", APP_HOST, APP_PROGRAM),
        *[_rec(tue - timedelta(hours=12) + timedelta(seconds=5 * i), "APP_USER", "SELECT", APP_HOST, APP_PROGRAM,
               obj="CUSTOMERS", sql="SELECT * FROM app.customers WHERE id = :1") for i in range(40)],
        # Approved change: a DBA grants a role inside the change window (must not alert)
        _rec(tue, "DBA_ALICE", "LOGON", DBA_HOST, "SQL Developer"),
        _rec(tue + timedelta(minutes=2), "DBA_ALICE", "GRANT", DBA_HOST, "SQL Developer",
             sql="GRANT DBA TO NEW_DBA_BOB"),
        # --- the bad night ---
        # SYS password guessing from an unknown host
        *[_rec(wed + timedelta(seconds=20 * i), "SYS", "LOGON", "198.51.100.44", "sqlplus", rc=1017)
          for i in range(6)],
        _rec(wed + timedelta(minutes=3), "SYS", "LOGON", "198.51.100.44", "sqlplus"),
        # The app account used from a laptop with a different tool
        _rec(wed + timedelta(minutes=10), "APP_USER", "LOGON", "laptop77.example", "SQL Developer"),
        *[_rec(wed + timedelta(minutes=11, seconds=6 * i), "APP_USER", "SELECT", "laptop77.example", "SQL Developer",
               obj="CARD_DATA", sql="SELECT * FROM app.card_data") for i in range(25)],
        # Privilege grant outside the window
        _rec(wed + timedelta(minutes=15), "SYS", "GRANT", "198.51.100.44", "sqlplus",
             sql="GRANT DBA TO APP_USER"),
        # Audit evasion
        _rec(wed + timedelta(minutes=16), "SYS", "NOAUDIT", "198.51.100.44", "sqlplus",
             sql="NOAUDIT POLICY ORA_LOGON_FAILURES"),
        _rec(wed + timedelta(minutes=17), "SYS", "DROP AUDIT POLICY", "198.51.100.44", "sqlplus",
             sql="DROP AUDIT POLICY APP_SENSITIVE_ACCESS"),
    ]
    return out


SERVICE_ACCOUNTS = {"APP_USER": {APP_PROGRAM}, "BATCH_ETL": {"python3"}}
