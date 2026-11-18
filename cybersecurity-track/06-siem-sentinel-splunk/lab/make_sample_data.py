"""Generate the synthetic multi-source logs in ./data (deterministic, offline).

You do not need to run this: the generated files are already in the repo.
Run it only if you want to change the story:  python make_sample_data.py

Fake data only: documentation IP ranges (192.0.2.0/24 internal, 198.51.100.0/24 and
203.0.113.0/24 external), *.example domains, made-up users.
"""

from __future__ import annotations

import base64
import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
DAY = datetime(2026, 11, 10)
rng = random.Random(1010)

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
USER_IP = {u: f"192.0.2.{11 + i}" for i, u in enumerate(USERS)}  # 192.0.2.11 .. .18


def t(h: int, m: int = 0, s: int = 0) -> datetime:
    return DAY + timedelta(hours=h, minutes=m, seconds=s)


def iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def b64ps(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode()


# ------------------------------------------------------------------ Windows security
def windows() -> list[dict]:
    ev = []

    def add(when, eid, comp, **kw):
        ev.append({"TimeCreated": iso(when), "EventID": eid, "Computer": comp, **kw})

    # normal logons
    for i, u in enumerate(USERS):
        for k in range(4):
            add(t(8 + k * 2, rng.randint(0, 59), rng.randint(0, 59)), 4624, f"WS-{u.upper()}",
                TargetUserName=u, IpAddress=USER_IP[u], LogonType=2 if k % 2 == 0 else 3)
    # brute force on the RDP server: 12 failures in 4 minutes
    for k in range(12):
        add(t(2, 10, k * 20), 4625, "RDP-SRV-01", TargetUserName="admin01",
            IpAddress="203.0.113.50", LogonType=10)
    # benign: a user mistypes the password 3 times
    for k in range(3):
        add(t(9, 5, k * 25), 4625, "WS-BOB", TargetUserName="bob", IpAddress="192.0.2.30", LogonType=2)
    # benign: a stale service password, 10 failures spread over 5 hours (not a burst)
    for k in range(10):
        add(t(3 + k // 2, 30 * (k % 2)), 4625, "SQL-01", TargetUserName="svc-backup",
            IpAddress="192.0.2.60", LogonType=3)
    # group membership changes
    add(t(23, 50), 4728, "DC-01", SubjectUserName="helpdesk1", Group="Domain Admins", MemberName="tmp-contractor")
    add(t(10, 20), 4728, "DC-01", SubjectUserName="helpdesk1", Group="Marketing-Share", MemberName="carol")
    add(t(11, 0), 4732, "DC-01", SubjectUserName="svc-provisioning", Group="Administrators", MemberName="svc-deploy2")
    # process creation (4688)
    ps_enc = b64ps("Write-Output 'hello lab'")
    add(t(14, 41), 4688, "HR-WS-12", SubjectUserName="erin", NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ParentProcessName="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        CommandLine=f"powershell.exe -NoProfile -w hidden -EncodedCommand {ps_enc}")
    add(t(2, 10), 4688, "FIN-WS-07", SubjectUserName="svc-sccm", NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ParentProcessName="C:\\Windows\\CCM\\CcmExec.exe",
        CommandLine=f"powershell.exe -NoProfile -enc {ps_enc}")
    add(t(1, 0), 4688, "SQL-01", SubjectUserName="svc-backup", NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ParentProcessName="C:\\Windows\\System32\\svchost.exe",
        CommandLine="powershell.exe -ExecutionPolicy Bypass -File D:\\scripts\\backup.ps1")
    for u, proc in [("alice", "chrome.exe"), ("bob", "excel.exe"), ("carol", "notepad.exe"), ("dave", "cmd.exe"),
                    ("frank", "outlook.exe"), ("grace", "code.exe")]:
        add(t(9 + rng.randint(0, 6), rng.randint(0, 59)), 4688, f"WS-{u.upper()}", SubjectUserName=u,
            NewProcessName=f"C:\\Program Files\\App\\{proc}", ParentProcessName="C:\\Windows\\explorer.exe",
            CommandLine=proc)
    return sorted(ev, key=lambda e: e["TimeCreated"])


# ------------------------------------------------------------------ Entra ID sign-ins
def entra() -> list[dict]:
    ev = []

    def add(when, user, ip, country, result=0, app="Office 365"):
        ev.append({"createdDateTime": iso(when), "userPrincipalName": f"{user}@corp.example",
                   "ipAddress": ip, "location": country, "appDisplayName": app,
                   "status": {"errorCode": result}})

    for u in USERS:
        add(t(8, rng.randint(0, 59)), u, USER_IP[u], "US")
        add(t(13, rng.randint(0, 59)), u, USER_IP[u], "US")
    # password spray: 10 users, one attempt each, wrong password (50126)
    spray_users = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy"]
    for k, u in enumerate(spray_users):
        add(t(2, 0, k * 40), u, "198.51.100.66", "NL", result=50126)
    add(t(2, 7), "bob", "198.51.100.66", "NL", result=0)  # the spray hit one account
    # benign: shared office NAT, 3 users mistype
    for k, u in enumerate(["carol", "dave", "erin"]):
        add(t(9, 40, k * 50), u, "192.0.2.40", "US", result=50126)
    # impossible travel: alice US then RO, 30 minutes apart
    add(t(9, 0), "alice", "192.0.2.11", "US")
    add(t(9, 30), "alice", "198.51.100.120", "RO")
    # benign: dave US then JP twelve hours later (possible by plane)
    add(t(8, 0), "dave", "192.0.2.14", "US", app="Teams")
    add(t(20, 0), "dave", "198.51.100.130", "JP", app="Teams")
    return sorted(ev, key=lambda e: e["createdDateTime"])


# ------------------------------------------------------------------ firewall
def firewall() -> list[list]:
    rows = []
    hosts = [USER_IP[u] for u in USERS]
    for _ in range(40):
        rows.append([iso(t(rng.randint(8, 17), rng.randint(0, 59), rng.randint(0, 59))), rng.choice(hosts),
                     rng.choice(["198.51.100.10", "198.51.100.11", "203.0.113.10"]),
                     rng.choice([443, 443, 443, 80]), "tcp", "allow", rng.randint(2_000, 90_000)])
    for k in range(5):
        rows.append([iso(t(9 + k, 15)), hosts[k], "192.0.2.53", 53, "udp", "allow", 120])
    # benign: an internal dev tool uses 8443 (on the common list)
    rows.append([iso(t(11, 30)), "192.0.2.25", "198.51.100.12", 8443, "tcp", "allow", 40_000])
    # the attacker is blocked at the edge: RDP denied
    for k in range(6):
        rows.append([iso(t(2, 10, k * 40)), "203.0.113.50", "192.0.2.5", 3389, "tcp", "deny", 0])
    # suspicious: the HR workstation (after the macro) talks to a rare port, 3 flows, a lot of data
    for k, mb in enumerate([300, 450, 600]):
        rows.append([iso(t(14, 45 + k * 5)), "192.0.2.77", "203.0.113.80", 4444, "tcp", "allow", mb * 1_000_000])
    rows.sort(key=lambda r: r[0])
    return rows


# ------------------------------------------------------------------ Linux auth.log
def linux() -> list[str]:
    lines = []

    def add(when, text):
        lines.append(f"{when.strftime('%b %d %H:%M:%S')} {text}")

    for k in range(11):  # brute force on ssh as root
        add(t(3, 0, k * 15), f"web01 sshd[{2200 + k}]: Failed password for root from 203.0.113.77 port {50000 + k} ssh2")
    for k in range(2):  # benign: an admin mistypes twice
        add(t(10, 5, k * 30), f"web01 sshd[{3100 + k}]: Failed password for deploy from 192.0.2.50 port {41000 + k} ssh2")
    add(t(10, 6), "web01 sshd[3102]: Accepted publickey for deploy from 192.0.2.50 port 41002 ssh2: RSA SHA256:abc")
    add(t(8, 30), "web01 sshd[2900]: Accepted password for grace from 192.0.2.17 port 40222 ssh2")
    add(t(9, 12), "web01 sudo:    grace : TTY=pts/0 ; PWD=/home/grace ; USER=root ; COMMAND=/usr/bin/apt update")
    add(t(9, 13), "web01 CRON[1234]: pam_unix(cron:session): session opened for user root")
    lines.sort(key=lambda s: s[:15])
    return lines


def main() -> None:
    DATA.mkdir(exist_ok=True)
    (DATA / "windows_security.jsonl").write_text("\n".join(json.dumps(e) for e in windows()) + "\n", encoding="utf-8")
    (DATA / "entra_signins.jsonl").write_text("\n".join(json.dumps(e) for e in entra()) + "\n", encoding="utf-8")
    with open(DATA / "firewall.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["time", "src_ip", "dst_ip", "dst_port", "proto", "action", "bytes_out"])
        w.writerows(firewall())
    (DATA / "linux_auth.log").write_text("\n".join(linux()) + "\n", encoding="utf-8")
    print("wrote", sorted(p.name for p in DATA.iterdir()))


if __name__ == "__main__":
    main()
