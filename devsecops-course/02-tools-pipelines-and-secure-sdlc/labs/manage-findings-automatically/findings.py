"""Normalize SARIF, ZAP JSON and npm audit JSON into ONE findings list, then manage it.

Steps: parse -> normalize severity -> fingerprint -> dedup -> apply waivers -> thresholds -> tickets.
Offline and pure Python. The "tickets" are plain dicts you could POST to Jira/GitLab/GitHub Issues.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date, timedelta
from urllib.parse import urlparse

import yaml

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: len(SEVERITIES) - i for i, s in enumerate(SEVERITIES)}  # critical=5 ... info=1


def _fp(kind: str, rule: str, location: str) -> str:
    return hashlib.sha1(f"{kind}|{rule}|{location}".encode()).hexdigest()[:12]


def _finding(tool, kind, rule, title, severity, location, cwe=(), fix="", line=None):
    return {"fingerprint": _fp(kind, rule, location), "tool": tool, "kind": kind, "rule": str(rule),
            "title": title, "severity": severity, "location": location, "cwe": list(cwe),
            "fix": fix, "occurrences": 1, "lines": [line] if line else []}


# ------------------------------------------------------------------ parsers


def _sarif_severity(rule_props: dict, level: str) -> str:
    score = rule_props.get("security-severity")
    if score is not None:
        s = float(score)
        return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "info"
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level, "medium")


def parse_sarif(doc: dict) -> list:
    out = []
    for run in doc.get("runs", []):
        driver = run["tool"]["driver"]
        rules = {r["id"]: r for r in driver.get("rules", [])}
        for res in run.get("results", []):
            rule = rules.get(res["ruleId"], {})
            props = rule.get("properties", {})
            loc = res["locations"][0]["physicalLocation"]
            cwe = [t for t in props.get("tags", []) if t.upper().startswith("CWE-")]
            title = rule.get("shortDescription", {}).get("text") or res["message"]["text"]
            out.append(_finding(driver["name"], "sast", res["ruleId"], title,
                                _sarif_severity(props, res.get("level", "warning")),
                                loc["artifactLocation"]["uri"], cwe, line=loc.get("region", {}).get("startLine")))
    return out


ZAP_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}


def parse_zap(doc: dict) -> list:
    out = []
    for site in doc.get("site", []):
        for alert in site.get("alerts", []):
            cwe = [f"CWE-{alert['cweid']}"] if alert.get("cweid") not in (None, "", "-1", "0") else []
            for inst in alert.get("instances", []):
                path = urlparse(inst["uri"]).path or "/"  # drop host and query: ?id=1 and ?id=2 are one issue
                out.append(_finding("zap", "dast", alert["pluginid"], alert["name"],
                                    ZAP_RISK[str(alert["riskcode"])], path, cwe, alert.get("solution", "")))
    return out


def parse_npm_audit(doc: dict) -> list:
    out = []
    for name, vuln in doc.get("vulnerabilities", {}).items():
        for via in vuln.get("via", []):
            if not isinstance(via, dict):  # a string means "vulnerable because of another package"
                continue
            fix = vuln.get("fixAvailable")
            fixtext = f"upgrade to {fix['name']}@{fix['version']}" if isinstance(fix, dict) else \
                ("a fix is available" if fix else "no fix available")
            out.append(_finding("npm-audit", "sca", f"npm-{via['source']}",
                                f"{via['name']}: {via['title']} ({via['range']})", via["severity"],
                                f"package:{via['name']}", via.get("cwe", []), fixtext))
    return out


def normalize(sarif=None, zap=None, npm=None) -> list:
    items = []
    if sarif:
        items += parse_sarif(sarif)
    if zap:
        items += parse_zap(zap)
    if npm:
        items += parse_npm_audit(npm)
    return items


# ------------------------------------------------------------------ dedup, waivers, thresholds


def dedup(items: list) -> list:
    """Merge items with the same fingerprint; keep the highest severity and count occurrences."""
    merged: dict = {}
    for f in items:
        cur = merged.get(f["fingerprint"])
        if not cur:
            merged[f["fingerprint"]] = dict(f, lines=list(f["lines"]))
            continue
        cur["occurrences"] += 1
        cur["lines"] += f["lines"]
        if RANK[f["severity"]] > RANK[cur["severity"]]:
            cur["severity"] = f["severity"]
    out = list(merged.values())
    out.sort(key=lambda f: (-RANK[f["severity"]], f["kind"], f["rule"], f["location"]))
    return out


def _as_date(v):
    return v if isinstance(v, date) else date.fromisoformat(str(v))


def apply_waivers(items: list, waivers: list, today: date) -> tuple:
    """Return (active, waived, expired_waivers). An expired waiver no longer hides anything."""
    active, waived, expired = [], [], []
    for w in waivers or []:
        if _as_date(w["expires"]) < today:
            expired.append(w)
    live = [w for w in (waivers or []) if _as_date(w["expires"]) >= today]
    for f in items:
        hit = next((w for w in live if str(w["rule"]) == f["rule"] and w["location"] == f["location"]), None)
        (waived if hit else active).append(dict(f, waiver=hit["reason"]) if hit else f)
    return active, waived, expired


def count_by_severity(items: list) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in items:
        counts[f["severity"]] += 1
    return counts


def evaluate(items: list, break_build: dict) -> dict:
    counts = count_by_severity(items)
    breaches = {s: (counts[s], limit) for s, limit in break_build.items() if counts[s] > limit}
    return {"passed": not breaches, "counts": counts, "breaches": breaches}


# ------------------------------------------------------------------ tickets


def create_tickets(items: list, existing: list, policy: dict, today: date) -> dict:
    """Create tickets for NEW findings only (idempotent); list tickets whose finding has gone."""
    min_rank = RANK[policy.get("ticket_min_severity", "medium")]
    open_fps = {t["fingerprint"] for t in existing if t.get("status", "open") == "open"}
    current = {f["fingerprint"] for f in items}
    numbers = [int(m.group(1)) for t in existing if (m := re.search(r"-(\d+)$", t["key"]))]
    nxt = max(numbers, default=0) + 1
    sla = policy.get("sla_days", {"critical": 7, "high": 30, "medium": 90, "low": 180})
    created = []
    for f in items:
        if RANK[f["severity"]] < min_rank or f["fingerprint"] in open_fps:
            continue
        created.append({
            "key": f"SEC-{nxt}", "fingerprint": f["fingerprint"], "status": "open",
            "title": f"[{f['severity'].upper()}] {f['title']} ({f['location']})",
            "severity": f["severity"],
            "labels": ["security", f["kind"], f["tool"], f["severity"]],
            "due": (today + timedelta(days=sla[f["severity"]])).isoformat(),
            "description": {"rule": f["rule"], "location": f["location"], "cwe": f["cwe"],
                            "occurrences": f["occurrences"], "fix": f["fix"]},
        })
        nxt += 1
    to_close = [t["key"] for t in existing if t.get("status", "open") == "open" and t["fingerprint"] not in current]
    return {"created": created, "already_tracked": sorted(open_fps & current), "to_close": to_close}


def process(sarif, zap, npm, policy: dict, existing: list, today: date) -> dict:
    items = dedup(normalize(sarif, zap, npm))
    active, waived, expired = apply_waivers(items, policy.get("waivers", []), today)
    gate = evaluate(active, policy["break_build"])
    tickets = create_tickets(active, existing, policy, today)
    return {"findings": active, "waived": waived, "expired_waivers": expired, "gate": gate, "tickets": tickets,
            "raw_count": len(normalize(sarif, zap, npm))}


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_policy(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)
