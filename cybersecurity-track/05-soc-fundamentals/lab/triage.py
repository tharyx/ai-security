"""Alert triage simulator: enrich, score, map to ATT&CK, decide, write case notes.

Everything is offline and synthetic. The analyzer reads three local files:
  alerts.json        the alert queue
  threat_intel.json  a tiny offline threat-intel table (reputation of IPs, domains, hashes)
  context.json       asset and user context, authorized scanners, approved change windows

Scoring in plain words:
  score = rule base + intel + asset value + user value + timing + corroboration - benign context
A benign reason can lower a score, but it can NEVER excuse a malicious intel hit.

Run the demo:  python demo.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------- rule knowledge

SEVERITY_POINTS = {"low": 10, "medium": 25, "high": 40, "critical": 55}
ASSET_POINTS = {"low": 0, "medium": 5, "high": 10, "critical": 15}

# attack: list of (tactic, technique id, technique name)
# benign_intel_can_excuse: may a "benign" reputation make this alert harmless?
RULES: dict[str, dict] = {
    "impossible_travel": {"severity": "medium", "benign_intel_can_excuse": True,
                          "attack": [("Initial Access", "T1078", "Valid Accounts")],
                          "next": ["Check the sign-in logs for the user (MFA result, device, user agent)",
                                   "Ask the user or manager if they travel or use a VPN",
                                   "If not explained: reset the password, revoke sessions"]},
    "password_spray": {"severity": "high", "benign_intel_can_excuse": False,
                       "attack": [("Credential Access", "T1110.003", "Password Spraying")],
                       "next": ["Block the source IP at the edge",
                                "List every account that logged in successfully from this IP",
                                "Force password reset and revoke sessions for those accounts"]},
    "success_after_failures": {"severity": "critical", "benign_intel_can_excuse": False,
                               "attack": [("Credential Access", "T1110", "Brute Force"),
                                          ("Initial Access", "T1078", "Valid Accounts")],
                               "next": ["Treat the account as compromised until proven otherwise",
                                        "Disable the account or reset password, revoke tokens",
                                        "Review everything the account did after the login"]},
    "brute_force": {"severity": "medium", "benign_intel_can_excuse": False,
                    "attack": [("Credential Access", "T1110.001", "Password Guessing")],
                    "next": ["Check if any login from this IP succeeded",
                             "Block the IP if it is outside your business regions",
                             "Check the account for lockout or strange activity"]},
    "port_scan": {"severity": "low", "benign_intel_can_excuse": True,
                  "attack": [("Discovery", "T1046", "Network Service Discovery")],
                  "next": ["Confirm the source against the authorized scanner list",
                           "If unknown, find which host owns the IP and block it"]},
    "encoded_powershell": {"severity": "high", "benign_intel_can_excuse": False,
                           "attack": [("Execution", "T1059.001", "PowerShell"),
                                      ("Defense Evasion", "T1027", "Obfuscated Files or Information")],
                           "next": ["Decode the command (offline) and read it",
                                    "Look at the parent process and what the host connected to",
                                    "Isolate the host if the command downloads or runs code"]},
    "av_detection": {"severity": "medium", "benign_intel_can_excuse": True,
                     "attack": [("Execution", "T1204.002", "User Execution: Malicious File")],
                     "next": ["Check the file hash against intel and the software inventory",
                              "Confirm the AV action (blocked, quarantined, or alert only)",
                              "If alert only and unknown, isolate the host and collect the file"]},
    "new_admin_member": {"severity": "high", "benign_intel_can_excuse": False,
                         "attack": [("Persistence", "T1098", "Account Manipulation")],
                         "next": ["Find the change ticket and the approver",
                                  "Ask the actor out-of-band (phone or chat) if it was them",
                                  "If not approved: remove the member and disable both accounts"]},
    "phishing_report": {"severity": "medium", "benign_intel_can_excuse": False,
                        "attack": [("Initial Access", "T1566.002", "Phishing: Spearphishing Link")],
                        "next": ["Search the mail system for the same sender, subject and link",
                                 "Delete the mail from all mailboxes",
                                 "Reset the password of everyone who clicked, block the domain"]},
    "data_exfil_volume": {"severity": "high", "benign_intel_can_excuse": False,
                          "attack": [("Exfiltration", "T1567.002", "Exfiltration to Cloud Storage")],
                          "next": ["Find out what data left (file names, sizes, classification)",
                                   "Check whether the user's account was compromised",
                                   "Preserve proxy logs and involve the data owner and legal if needed"]},
}

VERDICTS = ("true_positive", "benign_true_positive", "false_positive", "needs_investigation")

# ---------------------------------------------------------------- data loading


def load_json(name: str, base: Path = HERE):
    return json.loads((base / name).read_text(encoding="utf-8"))


def load_intel(base: Path = HERE) -> dict[str, dict]:
    return {i["indicator"].lower(): i for i in load_json("threat_intel.json", base)["indicators"]}


def load_context(base: Path = HERE) -> dict:
    return load_json("context.json", base)


def load_alerts(base: Path = HERE) -> list[dict]:
    return load_json("alerts.json", base)


# ---------------------------------------------------------------- result object


@dataclass
class Triage:
    alert: dict
    score: int = 0
    verdict: str = "needs_investigation"
    escalation: str = ""
    attack: list = field(default_factory=list)
    reasons: list = field(default_factory=list)      # (points, text)
    intel_hits: list = field(default_factory=list)
    benign_reasons: list = field(default_factory=list)
    corroborating: list = field(default_factory=list)
    notes: str = ""

    @property
    def id(self) -> str:
        return self.alert["id"]


# ---------------------------------------------------------------- helpers


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def _observables(alert: dict) -> list[str]:
    out = []
    for key in ("src_ip", "domain", "file_hash"):
        if alert.get(key):
            out.append(alert[key])
    return out


def lookup_intel(alert: dict, intel: dict[str, dict]) -> list[dict]:
    return [intel[o.lower()] for o in _observables(alert) if o.lower() in intel]


def find_change_window(alert: dict, ctx: dict) -> dict | None:
    """An approved change counts only if host, actor AND time all match."""
    when = _parse(alert["time"])
    for w in ctx.get("change_windows", []):
        if w["host"] != alert.get("host") or w["actor"] != alert.get("user"):
            continue
        if _parse(w["start"]) <= when <= _parse(w["end"]):
            ticket = alert.get("details", {}).get("change_ticket")
            if ticket and ticket != w["ticket"]:
                continue
            return w
    return None


def _base_score(alert: dict, intel: dict, ctx: dict) -> Triage:
    """Everything except corroboration."""
    rule = RULES[alert["rule"]]
    t = Triage(alert=alert, attack=list(rule["attack"]))
    d = alert.get("details", {})

    def add(points: int, text: str):
        t.reasons.append((points, text))

    add(SEVERITY_POINTS[rule["severity"]], f"rule severity: {rule['severity']}")

    # --- intel
    t.intel_hits = lookup_intel(alert, intel)
    malicious = False
    for hit in t.intel_hits:
        if hit["verdict"] == "malicious":
            malicious = True
            add(round(35 * hit["confidence"]), f"intel: {hit['indicator']} is malicious ({hit['source']}, {','.join(hit['tags'])})")
        elif hit["verdict"] == "suspicious":
            add(round(20 * hit["confidence"]), f"intel: {hit['indicator']} is suspicious ({','.join(hit['tags'])})")
        elif hit["verdict"] == "benign" and rule["benign_intel_can_excuse"]:
            add(-round(40 * hit["confidence"]), f"intel: {hit['indicator']} is known good ({','.join(hit['tags'])})")
            reason = "test_file" if "test-file" in hit["tags"] else "known_good_intel"
            t.benign_reasons.append(reason)
        elif hit["verdict"] == "benign":
            t.reasons.append((0, f"intel: {hit['indicator']} has a benign reputation, but reputation is not intent (no discount)"))

    # --- asset and user value
    asset = ctx["assets"].get(alert.get("host", ""))
    if asset:
        add(ASSET_POINTS[asset["criticality"]], f"asset {alert['host']} is {asset['criticality']} ({asset['role']})")
    user = ctx["users"].get(alert.get("user", ""))
    if user and user.get("vip"):
        add(5, f"user {alert['user']} is a VIP")

    # --- timing
    hour = _parse(alert["time"]).hour
    if hour < 6 or hour >= 20:
        add(5, "outside business hours (UTC)")

    # --- rule specific evidence
    if alert["rule"] == "data_exfil_volume" and d.get("baseline_mb"):
        ratio = d["uploaded_mb"] / d["baseline_mb"]
        if ratio >= 10:
            add(10, f"upload is {ratio:.0f}x the user's baseline")
    if alert["rule"] == "phishing_report" and d.get("clicked", 0) > 0:
        add(10, f"{d['clicked']} recipient(s) clicked the link")

    # --- benign context (never applied against a malicious intel hit)
    if not malicious:
        if alert["rule"] == "port_scan" and alert.get("src_ip") in ctx.get("authorized_scanners", []):
            add(-45, "source is an authorized vulnerability scanner")
            t.benign_reasons.append("authorized_scanner")
        window = find_change_window(alert, ctx)
        if window:
            add(-50, f"inside approved change {window['ticket']}: {window['summary']}")
            t.benign_reasons.append("approved_change")
        if alert["rule"] == "impossible_travel" and user and user.get("travel_approved"):
            add(-40, f"HR travel record explains the location ({user.get('travel_note', 'approved travel')})")
            t.benign_reasons.append("travel_approved")
        if alert["rule"] == "brute_force" and d.get("failed_attempts", 99) < 5 and not d.get("success_after"):
            add(-20, f"only {d['failed_attempts']} failures and no success: below the useful threshold")
            t.benign_reasons.append("below_threshold")
    t.score = max(0, min(100, sum(p for p, _ in t.reasons)))
    return t


def _shared_keys(alert: dict) -> set[str]:
    keys = set()
    for k in ("src_ip", "domain"):
        if alert.get(k):
            keys.add(f"{k}:{alert[k]}")
    if alert.get("user") and alert["user"] not in ("multiple",):
        keys.add(f"user:{alert['user']}")
    return keys


def _decide(t: Triage, ctx: dict) -> None:
    malicious = any(h["verdict"] == "malicious" for h in t.intel_hits)
    reasons = t.benign_reasons
    if reasons and not malicious:
        if set(reasons) & {"authorized_scanner", "approved_change", "travel_approved", "test_file"}:
            t.verdict = "benign_true_positive"
        else:
            t.verdict = "false_positive"
    elif t.score >= 60:
        t.verdict = "true_positive"
    elif t.score >= 35:
        t.verdict = "needs_investigation"
    else:
        t.verdict = "false_positive"

    asset = ctx["assets"].get(t.alert.get("host", ""), {})
    if t.verdict == "true_positive":
        if t.score >= 85 or asset.get("criticality") == "critical":
            t.escalation = "escalate_L3_declare_incident"
        else:
            t.escalation = "escalate_L2"
    elif t.verdict == "needs_investigation":
        t.escalation = "L1_continue_enrichment"
    elif t.verdict == "benign_true_positive":
        t.escalation = "close_benign_and_document"
    else:
        t.escalation = "close_false_positive_and_tune"


def write_case_notes(t: Triage) -> str:
    a = t.alert
    lines = [
        f"CASE NOTES  {a['id']}  {a['rule']}  {a['time']}",
        f"What fired: rule '{a['rule']}' on host={a.get('host') or '-'} user={a.get('user') or '-'} "
        f"src_ip={a.get('src_ip') or '-'} domain={a.get('domain') or '-'}",
        f"Details: {json.dumps(a.get('details', {}), sort_keys=True)}",
        "Enrichment:",
    ]
    if t.intel_hits:
        for h in t.intel_hits:
            lines.append(f"  - intel {h['indicator']}: {h['verdict']} (confidence {h['confidence']}), {h['note']}")
    else:
        lines.append("  - no intel hits (absence of intel is not proof of safety)")
    for pts, text in t.reasons:
        lines.append(f"  - {pts:+d}  {text}")
    if t.corroborating:
        lines.append(f"  - related alerts: {', '.join(t.corroborating)}")
    lines.append(f"Score: {t.score}/100")
    lines.append("ATT&CK: " + "; ".join(f"{tac} / {tid} {name}" for tac, tid, name in t.attack))
    lines.append(f"Verdict: {t.verdict}")
    lines.append(f"Recommended action: {t.escalation}")
    lines.append("Next steps:")
    for step in RULES[a["rule"]]["next"]:
        lines.append(f"  * {step}")
    return "\n".join(lines)


# ---------------------------------------------------------------- public API


def triage_queue(alerts: list[dict], intel: dict[str, dict], ctx: dict) -> list[Triage]:
    """Triage every alert. Result is sorted by score, highest first."""
    results = [_base_score(a, intel, ctx) for a in alerts]
    strong = {t.id: _shared_keys(t.alert) for t in results if t.score >= 45}
    for t in results:
        mine = _shared_keys(t.alert)
        t.corroborating = sorted(oid for oid, keys in strong.items() if oid != t.id and mine & keys)
        bonus = min(20, 10 * len(t.corroborating))
        if bonus and not (t.benign_reasons and not any(h["verdict"] == "malicious" for h in t.intel_hits)):
            t.reasons.append((bonus, f"corroborated by {len(t.corroborating)} related strong alert(s)"))
            t.score = max(0, min(100, sum(p for p, _ in t.reasons)))
        _decide(t, ctx)
        t.notes = write_case_notes(t)
    return sorted(results, key=lambda t: (-t.score, t.id))


def triage_default() -> list[Triage]:
    return triage_queue(load_alerts(), load_intel(), load_context())
