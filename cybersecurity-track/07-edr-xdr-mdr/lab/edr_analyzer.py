"""Process-tree analyzer for Sysmon-like events, with a simulated response.

What it does:
  1. build_trees(): joins events into parent -> child process trees (per host).
  2. run_rules(): four detection rules (see RULES).
  3. recommend(): turns alerts into a response per host.
  4. SimulatedEDR: a fake "isolate host" / "kill process". It changes only an
     in-memory object. It never touches a network or a process.

Standard library only. Does not import sibling files.
"""

from __future__ import annotations

import base64
import re
from collections import defaultdict
from dataclasses import dataclass, field

# ---------- constants ----------------------------------------------------------------

OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"}
POWERSHELL = {"powershell.exe", "pwsh.exe"}
USER_WRITABLE = ("\\users\\", "\\programdata\\", "\\temp\\", "\\appdata\\", "\\public\\")
# LSASS callers we accept, by FULL PATH (a name alone is easy to fake).
LSASS_ALLOWED_PATHS = {
    "c:\\windows\\system32\\wininit.exe",
    "c:\\windows\\system32\\csrss.exe",
    "c:\\windows\\system32\\services.exe",
    "c:\\windows\\system32\\svchost.exe",
    "c:\\windows\\system32\\werfault.exe",
}
LSASS_ALLOWED_PREFIXES = ("c:\\programdata\\microsoft\\windows defender\\platform\\",)
PROCESS_VM_READ = 0x0010  # the access right that lets a tool read memory (dump credentials)

SEVERITY_POINTS = {"critical": 60, "high": 50, "medium": 35, "low": 10}
ISOLATE_AT = 80
INVESTIGATE_AT = 40

MITRE = {
    "EDR-001": "T1566.001 / T1059.001",
    "EDR-002": "T1105 / T1218",
    "EDR-003": "T1543.003",
    "EDR-004": "T1003.001",
}


def base_name(path: str | None) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


# ---------- data model ---------------------------------------------------------------

@dataclass
class ProcNode:
    host: str
    guid: str
    pid: int | None
    image: str
    command_line: str
    user: str
    parent_guid: str | None
    parent_image: str | None
    ts: str
    children: list["ProcNode"] = field(default_factory=list)


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    host: str
    guid: str | None
    evidence: str
    mitre: str

    @property
    def points(self) -> int:
        return SEVERITY_POINTS[self.severity]


@dataclass
class Response:
    host: str
    score: int
    action: str  # isolate_host | investigate | monitor
    reasons: list[str]
    requires_approval: bool = False


# ---------- trees --------------------------------------------------------------------

def build_trees(events: list[dict]) -> dict[str, list[ProcNode]]:
    """Return {host: [root nodes]}. A node whose parent was never seen becomes a root."""
    nodes: dict[tuple[str, str], ProcNode] = {}
    for e in sorted(events, key=lambda x: x["ts"]):
        if e["event_id"] != 1:
            continue
        nodes[(e["host"], e["guid"])] = ProcNode(
            host=e["host"], guid=e["guid"], pid=e.get("pid"), image=e["image"],
            command_line=e.get("command_line", ""), user=e.get("user", ""),
            parent_guid=e.get("parent_guid"), parent_image=e.get("parent_image"), ts=e["ts"],
        )
    roots: dict[str, list[ProcNode]] = defaultdict(list)
    for (host, _), node in nodes.items():
        parent = nodes.get((host, node.parent_guid)) if node.parent_guid else None
        (parent.children if parent else roots[host]).append(node)
    return dict(roots)


def render_tree(node: ProcNode, depth: int = 0) -> list[str]:
    cmd = node.command_line if len(node.command_line) <= 70 else node.command_line[:67] + "..."
    lines = [f"{'    ' * depth}{'+-- ' if depth else ''}{base_name(node.image)} [{node.pid}] {cmd}"]
    for child in node.children:
        lines += render_tree(child, depth + 1)
    return lines


# ---------- helpers for rules --------------------------------------------------------

def encoded_command(cmdline: str) -> str | None:
    """Return the base64 text after -e / -enc / -EncodedCommand, or None.

    PowerShell accepts any prefix of -EncodedCommand (-e, -en, -enc ...) and the alias -ec.
    """
    tokens = cmdline.split()
    for i, tok in enumerate(tokens[:-1]):
        t = tok.lower()
        if t == "-ec" or (t.startswith("-e") and "-encodedcommand".startswith(t)):
            blob = tokens[i + 1]
            if re.fullmatch(r"[A-Za-z0-9+/=]{16,}", blob):
                return blob
    return None


def decode_ps(blob: str) -> str:
    try:
        return base64.b64decode(blob).decode("utf-16-le", errors="replace")
    except Exception:  # not valid base64
        return "<undecodable>"


def _in_user_writable(path: str) -> bool:
    p = path.lower().replace("/", "\\")
    return any(seg in p for seg in USER_WRITABLE)


# ---------- rules --------------------------------------------------------------------

def rule_office_encoded_powershell(events: list[dict]) -> list[Alert]:
    out = []
    for e in events:
        if e["event_id"] != 1:
            continue
        if base_name(e["image"]) in POWERSHELL and base_name(e.get("parent_image")) in OFFICE_APPS:
            blob = encoded_command(e.get("command_line", ""))
            if blob:
                out.append(Alert(
                    "EDR-001", "Office app spawned PowerShell with an encoded command", "high",
                    e["host"], e["guid"],
                    f"parent={base_name(e['parent_image'])} decoded='{decode_ps(blob)[:80]}'",
                    MITRE["EDR-001"]))
    return out


def rule_lolbin_abuse(events: list[dict]) -> list[Alert]:
    out = []
    for e in events:
        if e["event_id"] != 1:
            continue
        name, cmd = base_name(e["image"]), e.get("command_line", "").lower()
        why = None
        if name == "certutil.exe" and ("-urlcache" in cmd or "-verifyctl" in cmd) and "http" in cmd:
            why = "certutil downloads a file from a URL"
        elif name == "rundll32.exe":
            dll = cmd.split("rundll32.exe", 1)[-1]
            if "javascript:" in cmd or _in_user_writable(dll):
                why = "rundll32 loads code from a user-writable path or script"
        elif name == "mshta.exe" and re.search(r"https?://|javascript:|vbscript:", cmd):
            why = "mshta runs remote or script content"
        if why:
            out.append(Alert("EDR-002", f"LOLBin abuse: {why}", "medium", e["host"], e["guid"],
                             f"cmd={e['command_line'][:90]}", MITRE["EDR-002"]))
    return out


def rule_suspicious_service(events: list[dict]) -> list[Alert]:
    out = []
    for e in events:
        if e["event_id"] != 7045:
            continue
        path = e.get("service_file", "")
        lower = path.lower()
        shell = any(s in lower for s in ("cmd.exe /c", "powershell", "-enc"))
        if shell or _in_user_writable(path):
            out.append(Alert("EDR-003", "Service installed from a suspicious location", "high",
                             e["host"], None,
                             f"service={e.get('service_name')} file={path}", MITRE["EDR-003"]))
    return out


def rule_lsass_access(events: list[dict]) -> list[Alert]:
    out = []
    for e in events:
        if e["event_id"] != 10 or base_name(e.get("target_image")) != "lsass.exe":
            continue
        mask = int(str(e.get("granted_access", "0")), 16)
        if not mask & PROCESS_VM_READ:
            continue  # cannot read memory: not a credential-dump right
        src = e["image"].lower()
        if src in LSASS_ALLOWED_PATHS or src.startswith(LSASS_ALLOWED_PREFIXES):
            continue
        out.append(Alert("EDR-004", "Non-system process read LSASS memory", "critical",
                         e["host"], e.get("guid"),
                         f"source={e['image']} access={e['granted_access']}", MITRE["EDR-004"]))
    return out


RULES = [rule_office_encoded_powershell, rule_lolbin_abuse, rule_suspicious_service,
         rule_lsass_access]


def run_rules(events: list[dict]) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in RULES:
        alerts += rule(events)
    return alerts


# ---------- recommendation -----------------------------------------------------------

def recommend(alerts: list[Alert], protected_hosts: set[str] | None = None) -> list[Response]:
    """One response per host. Score = sum of alert points (+20 if 3+ rules fire), max 100."""
    protected_hosts = protected_hosts or set()
    by_host: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        by_host[a.host].append(a)
    responses = []
    for host, items in by_host.items():
        score = min(100, sum(a.points for a in items))
        if len({a.rule_id for a in items}) >= 3:
            score = min(100, score + 20)  # many different behaviours on one host look like a campaign
        action = ("isolate_host" if score >= ISOLATE_AT
                  else "investigate" if score >= INVESTIGATE_AT else "monitor")
        responses.append(Response(
            host=host, score=score, action=action,
            reasons=sorted({a.rule_id for a in items}),
            requires_approval=(action == "isolate_host" and host in protected_hosts)))
    return sorted(responses, key=lambda r: -r.score)


# ---------- simulated response -------------------------------------------------------

class SimulatedEDR:
    """Pretend EDR console. Only in-memory state changes."""

    def __init__(self) -> None:
        self.isolated: set[str] = set()
        self.killed: list[tuple[str, str]] = []
        self.audit: list[str] = []

    def isolate_host(self, host: str, approved: bool = False, protected: bool = False) -> str:
        if protected and not approved:
            msg = f"REFUSED isolate {host}: protected host needs human approval"
        elif host in self.isolated:
            msg = f"NOOP {host} already isolated"
        else:
            self.isolated.add(host)
            msg = f"ISOLATED {host} (simulated: only the EDR channel stays open)"
        self.audit.append(msg)
        return msg

    def kill_process(self, host: str, guid: str) -> str:
        self.killed.append((host, guid))
        msg = f"KILLED process {guid} on {host} (simulated)"
        self.audit.append(msg)
        return msg

    def execute(self, response: Response, approved: bool = False) -> str:
        if response.action == "isolate_host":
            return self.isolate_host(response.host, approved=approved,
                                     protected=response.requires_approval)
        msg = f"NO AUTOMATIC ACTION for {response.host}: {response.action}"
        self.audit.append(msg)
        return msg
