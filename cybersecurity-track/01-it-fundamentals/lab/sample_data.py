"""Synthetic logs for the IT-fundamentals lab. All IPs are documentation ranges, all hosts *.example."""

import json


def _win(time, eid, computer, channel, **data):
    return {"TimeCreated": time, "EventID": eid, "Computer": computer, "Channel": channel, "EventData": data}


def _fail(sec, user, ip="203.0.113.50"):
    return _win(f"2026-11-02T09:00:{sec:02d}Z", 4625, "srv01.corp.example", "Security",
                TargetUserName=user, IpAddress=ip, LogonType=3)


# Windows Security / System events, exported as JSON (like Get-WinEvent | ConvertTo-Json).
WINDOWS_EVENTS = [
    _win("2026-11-02T08:55:10Z", 4624, "ws01.corp.example", "Security",
         TargetUserName="alice", IpAddress="192.0.2.10", LogonType=2),
    # brute-force burst against srv01: 6 failures in 15 seconds, then a success
    _fail(1, "administrator"), _fail(4, "admin"), _fail(7, "administrator"),
    _fail(10, "backup"), _fail(13, "administrator"), _fail(16, "administrator"),
    _win("2026-11-02T09:00:19Z", 4624, "srv01.corp.example", "Security",
         TargetUserName="administrator", IpAddress="203.0.113.50", LogonType=3),
    # one normal typo: two failures only, not a burst
    _win("2026-11-02T10:10:00Z", 4625, "ws02.corp.example", "Security",
         TargetUserName="bob", IpAddress="192.0.2.11", LogonType=2),
    _win("2026-11-02T10:10:09Z", 4625, "ws02.corp.example", "Security",
         TargetUserName="bob", IpAddress="192.0.2.11", LogonType=2),
    _win("2026-11-02T10:10:20Z", 4624, "ws02.corp.example", "Security",
         TargetUserName="bob", IpAddress="192.0.2.11", LogonType=2),
    # new local account
    _win("2026-11-02T09:05:30Z", 4720, "srv01.corp.example", "Security",
         TargetUserName="svc_backup2", SubjectUserName="administrator"),
    # process creation with encoded PowerShell
    _win("2026-11-02T09:06:00Z", 4688, "srv01.corp.example", "Security",
         NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         CommandLine="powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
         ParentProcessName="C:\\Windows\\System32\\cmd.exe", SubjectUserName="administrator"),
    # new service pointing at a user-writable folder
    _win("2026-11-02T09:07:12Z", 7045, "srv01.corp.example", "System",
         ServiceName="WinUpdateHelper", ImagePath="C:\\Users\\Public\\updater.exe", AccountName="LocalSystem"),
    # a normal service install from Program Files
    _win("2026-11-02T11:00:00Z", 7045, "ws01.corp.example", "System",
         ServiceName="ExampleAgent", ImagePath="C:\\Program Files\\Example Agent\\agent.exe",
         AccountName="LocalSystem"),
]

WINDOWS_JSON = json.dumps(WINDOWS_EVENTS, indent=2)

# Linux /var/log/auth.log (Debian/Ubuntu style).
AUTH_LOG = """\
Nov  2 09:00:01 web01 sshd[2101]: Failed password for invalid user admin from 198.51.100.77 port 50001 ssh2
Nov  2 09:00:03 web01 sshd[2101]: Failed password for invalid user oracle from 198.51.100.77 port 50002 ssh2
Nov  2 09:00:05 web01 sshd[2101]: Failed password for root from 198.51.100.77 port 50003 ssh2
Nov  2 09:00:07 web01 sshd[2101]: Failed password for root from 198.51.100.77 port 50004 ssh2
Nov  2 09:00:09 web01 sshd[2101]: Failed password for root from 198.51.100.77 port 50005 ssh2
Nov  2 09:00:11 web01 sshd[2101]: Failed password for root from 198.51.100.77 port 50006 ssh2
Nov  2 09:00:14 web01 sshd[2101]: Accepted password for root from 198.51.100.77 port 50007 ssh2
Nov  2 09:01:02 web01 useradd[2150]: new user: name=support9, UID=1005, GID=1005, home=/home/support9, shell=/bin/bash
Nov  2 09:01:20 web01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo support9
Nov  2 09:02:00 web01 CRON[2200]: pam_unix(cron:session): session opened for user root by (uid=0)
Nov  2 10:30:00 web01 sshd[2300]: Accepted publickey for deploy from 192.0.2.25 port 41000 ssh2
Nov  2 10:45:10 web01 sshd[2310]: Failed password for deploy from 192.0.2.25 port 41022 ssh2
"""
