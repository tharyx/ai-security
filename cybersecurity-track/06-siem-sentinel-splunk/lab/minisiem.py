"""A mini SIEM: parse -> normalize -> detect -> alert. Offline, standard library + pyyaml.

Pipeline (the same four steps every real SIEM does):
  1. INGEST     read raw logs from four different sources (each has its own format)
  2. NORMALIZE  map every source to one common schema (Event)
  3. DETECT     run Sigma-like YAML rules over the normalized events
  4. ALERT      one Alert per rule match, with evidence

The rule format is "Sigma-like": a `detection` block (selection / filter / condition) plus an
`aggregation` block for counting. Real Sigma is richer; this is a small teaching version.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
YEAR = 2026  # syslog lines have no year

# ------------------------------------------------------------------ common schema


@dataclass
class Event:
    id: str
    ts: datetime
    source: str                 # windows | entra | firewall | linux
    action: str                 # logon_failure | logon_success | group_add | process_create | network_allow | network_deny
    host: str = ""
    user: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    country: str = ""
    process: str = ""
    parent_process: str = ""
    command_line: str = ""
    group: str = ""
    member: str = ""
    bytes_out: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ts"] = self.ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        return d


def _ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------ parsers

WIN_ACTIONS = {4624: "logon_success", 4625: "logon_failure", 4728: "group_add",
               4732: "group_add", 4756: "group_add", 4688: "process_create"}


def parse_windows(lines) -> list[Event]:
    out = []
    for n, line in enumerate(lines):
        if not line.strip():
            continue
        r = json.loads(line)
        action = WIN_ACTIONS.get(r["EventID"])
        if not action:
            continue
        ev = Event(id=f"win-{n}", ts=_ts(r["TimeCreated"]), source="windows", action=action, host=r["Computer"])
        if action in ("logon_success", "logon_failure"):
            ev.user, ev.src_ip = r["TargetUserName"], r.get("IpAddress", "")
        elif action == "group_add":
            ev.user, ev.group, ev.member = r["SubjectUserName"], r["Group"], r["MemberName"]
        else:
            ev.user = r["SubjectUserName"]
            ev.process, ev.parent_process, ev.command_line = r["NewProcessName"], r["ParentProcessName"], r["CommandLine"]
        out.append(ev)
    return out


def parse_entra(lines) -> list[Event]:
    out = []
    for n, line in enumerate(lines):
        if not line.strip():
            continue
        r = json.loads(line)
        ok = r["status"]["errorCode"] == 0
        out.append(Event(id=f"entra-{n}", ts=_ts(r["createdDateTime"]), source="entra",
                         action="logon_success" if ok else "logon_failure",
                         user=r["userPrincipalName"].split("@")[0], src_ip=r["ipAddress"], country=r["location"]))
    return out


def parse_firewall(text: str) -> list[Event]:
    out = []
    for n, r in enumerate(csv.DictReader(text.splitlines())):
        out.append(Event(id=f"fw-{n}", ts=_ts(r["time"]), source="firewall",
                         action="network_allow" if r["action"] == "allow" else "network_deny",
                         src_ip=r["src_ip"], dst_ip=r["dst_ip"], dst_port=int(r["dst_port"]), bytes_out=int(r["bytes_out"])))
    return out


_SSH_FAIL = re.compile(r"^(\w{3} +\d+ [\d:]{8}) (\S+) sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\S+) port \d+")
_SSH_OK = re.compile(r"^(\w{3} +\d+ [\d:]{8}) (\S+) sshd\[\d+\]: Accepted \w+ for (\S+) from (\S+) port \d+")


def parse_linux(lines) -> list[Event]:
    out = []
    for n, line in enumerate(lines):
        for rx, action in ((_SSH_FAIL, "logon_failure"), (_SSH_OK, "logon_success")):
            m = rx.match(line)
            if m:
                when = datetime.strptime(f"{YEAR} {m.group(1)}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
                out.append(Event(id=f"lnx-{n}", ts=when, source="linux", action=action, host=m.group(2),
                                 user=m.group(3), src_ip=m.group(4)))
                break
        # lines we do not parse (sudo, cron...) are skipped, like an unparsed log in a real SIEM
    return out


def ingest(data_dir: Path | None = None) -> list[Event]:
    d = Path(data_dir) if data_dir else HERE / "data"
    events = []
    events += parse_windows((d / "windows_security.jsonl").read_text(encoding="utf-8").splitlines())
    events += parse_entra((d / "entra_signins.jsonl").read_text(encoding="utf-8").splitlines())
    events += parse_firewall((d / "firewall.csv").read_text(encoding="utf-8"))
    events += parse_linux((d / "linux_auth.log").read_text(encoding="utf-8").splitlines())
    return sorted(events, key=lambda e: (e.ts, e.id))


# ------------------------------------------------------------------ rules


def load_rules(rules_dir: Path | None = None) -> list[dict]:
    d = Path(rules_dir) if rules_dir else HERE / "rules"
    rules = [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.yml"))]
    for r in rules:
        validate_rule(r)
    return rules


def validate_rule(rule: dict) -> None:
    for key in ("title", "id", "level", "tags", "detection"):
        if key not in rule:
            raise ValueError(f"rule is missing '{key}'")
    det = rule["detection"]
    if "selection" not in det or "condition" not in det:
        raise ValueError(f"rule {rule['id']}: detection needs 'selection' and 'condition'")
    _condition_tokens(det["condition"], det)
    agg = rule.get("aggregation")
    if agg and agg["type"] not in ("count", "distinct_count", "country_change"):
        raise ValueError(f"rule {rule['id']}: unknown aggregation type {agg['type']}")


def _match_block(ev: dict, block: dict) -> bool:
    """All fields must match (AND). A list of values means any value (OR)."""
    for key, wanted in block.items():
        field_name, *mods = key.split("|")
        actual = ev.get(field_name, "")
        values = wanted if isinstance(wanted, list) else [wanted]
        a = str(actual).lower()
        ok = False
        for v in values:
            v = str(v).lower()
            if "contains" in mods:
                ok = v in a
            elif "startswith" in mods:
                ok = a.startswith(v)
            elif "endswith" in mods:
                ok = a.endswith(v)
            elif "re" in mods:
                ok = re.search(v, str(actual), re.I) is not None
            else:
                ok = a == v
            if ok:
                break
        if not ok:
            return False
    return True


def _condition_tokens(cond: str, det: dict) -> list[str]:
    tokens = cond.replace("(", " ( ").replace(")", " ) ").split()
    for tok in tokens:
        if tok in ("and", "or", "not", "(", ")"):
            continue
        if tok not in det or tok == "condition":
            raise ValueError(f"condition uses unknown name '{tok}'")
    return tokens


def _eval_condition(cond: str, det: dict, ev: dict) -> bool:
    """Tiny parser for: names, and, or, not, ( ). Precedence: not > and > or."""
    tokens = _condition_tokens(cond, det)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def p_or():
        val = p_and()
        while peek() == "or":
            take()
            val = p_and() or val
        return val

    def p_and():
        val = p_not()
        while peek() == "and":
            take()
            val = p_not() and val
        return val

    def p_not():
        if peek() == "not":
            take()
            return not p_not()
        if peek() == "(":
            take()
            val = p_or()
            take()  # ")"
            return val
        return _match_block(ev, det[take()])

    return p_or()


@dataclass
class Alert:
    rule_id: str
    title: str
    level: str
    tags: list
    time: str
    entity: dict
    count: int
    evidence: list = field(default_factory=list)

    @property
    def attack(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if t.startswith("attack.t")]


def run_rule(rule: dict, events: list[Event]) -> list[Alert]:
    det = rule["detection"]
    matched = [e for e in events if _eval_condition(det["condition"], det, e.to_dict())]
    agg = rule.get("aggregation")

    def make(evs: list[Event], entity: dict) -> Alert:
        return Alert(rule["id"], rule["title"], rule["level"], rule["tags"], evs[0].ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                     entity, len(evs), [e.id for e in evs])

    if not agg:
        return [make([e], {"host": e.host, "user": e.user}) for e in matched]

    groups: dict[tuple, list[Event]] = {}
    for e in matched:
        groups.setdefault(tuple(getattr(e, f) for f in agg["group_by"]), []).append(e)
    window = timedelta(minutes=agg["timeframe_minutes"])
    alerts = []
    for key, evs in groups.items():
        evs.sort(key=lambda e: e.ts)
        entity = dict(zip(agg["group_by"], key))
        hit = None
        if agg["type"] == "country_change":
            for a, b in zip(evs, evs[1:]):
                if getattr(a, agg["field"]) != getattr(b, agg["field"]) and b.ts - a.ts <= window:
                    hit = [a, b]
                    break
        else:
            for i, first in enumerate(evs):
                inside = [e for e in evs[i:] if e.ts - first.ts <= window]
                measure = len(inside) if agg["type"] == "count" else len({getattr(e, agg["field"]) for e in inside})
                if measure >= agg["threshold"]:
                    hit = inside
                    break
        if hit:
            alerts.append(make(hit, entity))
    return alerts


def run_all(rules: list[dict], events: list[Event]) -> list[Alert]:
    alerts = [a for r in rules for a in run_rule(r, events)]
    return sorted(alerts, key=lambda a: (a.time, a.rule_id))


# ------------------------------------------------------------------ exports for the real tools

COLUMNS = ["ts", "source", "action", "host", "user", "src_ip", "dst_ip", "dst_port", "country",
           "process", "parent_process", "command_line", "group", "member", "bytes_out"]
# `source`, `host` and `group` are special words in Splunk, so the CSV uses safer names.
SPLUNK_NAMES = {"source": "log_source", "host": "hostname", "group": "group_name"}


def export_csv(events: list[Event], path: Path) -> None:
    """CSV you can upload to Splunk (Settings > Add Data > Upload)."""
    names = [SPLUNK_NAMES.get(c, c) for c in COLUMNS]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(names)
        for e in events:
            d = e.to_dict()
            w.writerow([d[c] for c in COLUMNS])


def _kql_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def export_kql_datatable(events: list[Event], name: str = "Events") -> str:
    """A KQL `let` with a datatable of every event. Paste it above your query in Log Analytics or ADX."""
    cols = ("TimeGenerated:datetime, Source:string, Action:string, Host:string, User:string, SrcIp:string, DstIp:string, "
            "DstPort:int, Country:string, Process:string, ParentProcess:string, CommandLine:string, "
            "Group:string, Member:string, BytesOut:long")
    rows = []
    for e in events:
        d = e.to_dict()
        rows.append(f"    datetime({d['ts']}), {_kql_str(e.source)}, {_kql_str(e.action)}, {_kql_str(e.host)}, {_kql_str(e.user)}, "
                    f"{_kql_str(e.src_ip)}, {_kql_str(e.dst_ip)}, {e.dst_port}, {_kql_str(e.country)}, {_kql_str(e.process)}, "
                    f"{_kql_str(e.parent_process)}, {_kql_str(e.command_line)}, {_kql_str(e.group)}, {_kql_str(e.member)}, {e.bytes_out}")
    return f"let {name} = datatable({cols})\n[\n" + ",\n".join(rows) + "\n];\n"
