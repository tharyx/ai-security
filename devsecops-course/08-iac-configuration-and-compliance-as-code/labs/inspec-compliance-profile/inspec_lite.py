"""InSpec-style compliance runner (teaching tool, offline, no Ruby, no InSpec, no SSH).

Concepts mirrored from InSpec: profile (inspec.yml + controls/), control id, impact (0.0-1.0),
title, describe + resource + its + should / should_not + matcher, only_if, tags, JSON reporter.
The controls are written in a YAML DSL we define here; evaluation runs against a "facts" dict
(JSON) that stands in for the target host. A real InSpec profile is Ruby and talks to the host
over SSH/WinRM/local (see real-tools/inspec-cinc.md).

Includes an "at scale" fleet runner over generated fake hosts.
"""

from __future__ import annotations

import json
import random
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

RESOURCES = {"sshd_config", "package", "service", "file", "kernel_parameter", "user", "json", "os"}
MATCHERS = {"eq", "cmp", "be_in", "match", "include", "be_lte", "be_gte", "be_nil"}
MISSING = object()


# ------------------------------------------------------------------ profile loading and "inspec check"
@dataclass
class Control:
    id: str
    impact: float
    title: str
    desc: str
    tags: dict
    only_if: dict
    describe: list[dict]
    source: str = ""


@dataclass
class Profile:
    meta: dict
    controls: list[Control] = field(default_factory=list)


def load_profile(path: str | Path) -> Profile:
    root = Path(path)
    meta = yaml.safe_load((root / "inspec.yml").read_text(encoding="utf-8"))
    prof = Profile(meta)
    for f in sorted((root / "controls").glob("*.yml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        for c in doc.get("controls", []):
            prof.controls.append(Control(
                id=c.get("id", ""), impact=c.get("impact", -1), title=c.get("title", ""), desc=c.get("desc", ""),
                tags=c.get("tags", {}) or {}, only_if=c.get("only_if", {}) or {}, describe=c.get("describe", []) or [],
                source=f.name,
            ))
    return prof


def check_profile(profile: Profile) -> list[str]:
    """Like `inspec check`: structural errors in the profile."""
    errors: list[str] = []
    for key in ("name", "version", "title"):
        if not profile.meta.get(key):
            errors.append(f"inspec.yml: missing {key}")
    seen = set()
    for c in profile.controls:
        if not c.id or c.id in seen:
            errors.append(f"{c.source}: missing or duplicate control id {c.id!r}")
        seen.add(c.id)
        if not isinstance(c.impact, (int, float)) or not 0.0 <= c.impact <= 1.0:
            errors.append(f"{c.id}: impact must be between 0.0 and 1.0")
        if not c.title:
            errors.append(f"{c.id}: missing title")
        if not c.describe:
            errors.append(f"{c.id}: no describe blocks")
        for d in c.describe:
            if d.get("resource") not in RESOURCES:
                errors.append(f"{c.id}: unknown resource {d.get('resource')!r}")
            if "its" not in d:
                errors.append(f"{c.id}: describe block without its")
            clause = d.get("should") or d.get("should_not")
            if not isinstance(clause, dict) or len(clause) != 1 or next(iter(clause)) not in MATCHERS:
                errors.append(f"{c.id}: need exactly one should/should_not with a known matcher")
    return errors


def severity(impact: float) -> str:
    """InSpec's own mapping: <0.4 low, <0.7 medium, <0.9 high, else critical."""
    if impact < 0.01:
        return "none"
    if impact < 0.4:
        return "low"
    if impact < 0.7:
        return "medium"
    if impact < 0.9:
        return "high"
    return "critical"


# ------------------------------------------------------------------ resources over facts
def resource_value(facts: dict, resource: str, arg: str | None, its: str) -> Any:
    if resource == "sshd_config":
        return facts.get("sshd_config", {}).get(its, MISSING)
    if resource == "package":
        pkgs = facts.get("packages", {})
        return {"installed": arg in pkgs, "version": pkgs.get(arg)}.get(its, MISSING)
    if resource == "service":
        svc = facts.get("services", {}).get(arg)
        return {"installed": svc is not None, "enabled": bool(svc and svc.get("enabled")), "running": bool(svc and svc.get("running"))}.get(its, MISSING)
    if resource == "file":
        f = facts.get("files", {}).get(arg)
        return {"exist": f is not None, "mode": f.get("mode") if f else None, "owner": f.get("owner") if f else None}.get(its, MISSING)
    if resource == "kernel_parameter":
        return facts.get("kernel_parameters", {}).get(arg, MISSING) if its == "value" else MISSING
    if resource == "user":
        u = facts.get("users", {}).get(arg)
        return {"exists": u is not None, "uid": u.get("uid") if u else None, "shell": u.get("shell") if u else None}.get(its, MISSING)
    if resource == "json":
        return facts.get("json_files", {}).get(arg, {}).get(its, MISSING)
    if resource == "os":
        return facts.get("os", {}).get(its, MISSING)
    return MISSING


def to_number(x: Any) -> float | None:
    if isinstance(x, bool):
        return None
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def matches(matcher: str, expected: Any, actual: Any) -> bool:
    if actual is MISSING:
        return matcher == "be_nil" and expected is True
    if matcher == "eq":
        return actual == expected
    if matcher == "cmp":  # lenient: numbers compare numerically, strings case-insensitively
        a, e = to_number(actual), to_number(expected)
        if a is not None and e is not None:
            return a == e
        return str(actual).lower() == str(expected).lower()
    if matcher == "be_in":
        return actual in expected
    if matcher == "match":
        return isinstance(actual, str) and re.search(str(expected), actual) is not None
    if matcher == "include":
        if isinstance(actual, (list, tuple, str)):
            return expected in actual
        return False
    if matcher in {"be_lte", "be_gte"}:
        a = to_number(actual)
        if a is None:
            return False
        return a <= float(expected) if matcher == "be_lte" else a >= float(expected)
    if matcher == "be_nil":
        return (actual is None) == bool(expected)
    raise ValueError(f"unknown matcher {matcher}")


def only_if_ok(cond: dict, facts: dict) -> bool:
    if "os_family" in cond and facts.get("os", {}).get("family") not in cond["os_family"]:
        return False
    if "has_file" in cond and cond["has_file"] not in facts.get("files", {}):
        return False
    return True


def run_control(control: Control, facts: dict) -> dict:
    if not only_if_ok(control.only_if, facts):
        return {"id": control.id, "impact": control.impact, "title": control.title, "status": "skipped", "results": [], "tags": control.tags}
    results = []
    for d in control.describe:
        negate = "should_not" in d
        matcher, expected = next(iter((d.get("should_not") or d.get("should")).items()))
        actual = resource_value(facts, d["resource"], d.get("arg"), d["its"])
        ok = matches(matcher, expected, actual)
        if negate:
            ok = not ok if actual is not MISSING else True
        shown = "(missing)" if actual is MISSING else actual
        subject = f"{d['resource']}{'(' + d['arg'] + ')' if d.get('arg') else ''} {d['its']}"
        code_desc = f"{subject} should{'_not' if negate else ''} {matcher} {json.dumps(expected)}"
        results.append({"status": "passed" if ok else "failed", "code_desc": code_desc, "message": None if ok else f"got: {shown}"})
    status = "passed" if all(r["status"] == "passed" for r in results) else "failed"
    return {"id": control.id, "impact": control.impact, "title": control.title, "status": status, "results": results, "tags": control.tags}


def run_profile(profile: Profile, facts: dict) -> list[dict]:
    return [run_control(c, facts) for c in profile.controls]


def summarize(results: list[dict]) -> dict:
    counts = Counter(r["status"] for r in results)
    executed = counts["passed"] + counts["failed"]
    pct = round(100.0 * counts["passed"] / executed, 1) if executed else 100.0
    total_w = sum(r["impact"] for r in results if r["status"] != "skipped")
    failed_w = sum(r["impact"] for r in results if r["status"] == "failed")
    weighted = round(100.0 * (1 - failed_w / total_w), 1) if total_w else 100.0
    by_sev = Counter(severity(r["impact"]) for r in results if r["status"] == "failed")
    return {"passed": counts["passed"], "failed": counts["failed"], "skipped": counts["skipped"],
            "compliance_pct": pct, "risk_weighted_pct": weighted, "failed_by_severity": dict(by_sev)}


def to_inspec_json(profile: Profile, results: list[dict]) -> dict:
    """Shape loosely follows `inspec exec --reporter json` (verify against your InSpec version)."""
    return {"platform": {"name": "teaching-sim"}, "profiles": [{
        "name": profile.meta["name"], "version": profile.meta["version"], "title": profile.meta["title"],
        "controls": [{"id": r["id"], "impact": r["impact"], "title": r["title"], "tags": r["tags"],
                      "results": [{"status": x["status"], "code_desc": x["code_desc"], "message": x["message"]} for x in r["results"]]}
                     for r in results]}],
        "statistics": summarize(results)}


# ------------------------------------------------------------------ at scale: a fake fleet
def drift_fns():
    def root_login(h): h["sshd_config"]["PermitRootLogin"] = "yes"
    def telnet(h): h["packages"]["telnet"] = "0.17"
    def ip_forward(h): h["kernel_parameters"]["net.ipv4.ip_forward"] = 1
    def shadow(h): h["files"]["/etc/shadow"]["mode"] = "0644"
    def auditd_down(h): h["services"]["auditd"]["running"] = False
    def cbc(h): h["sshd_config"]["Ciphers"] = "aes128-cbc,aes256-gcm@openssh.com"
    def guest(h): h["users"]["guest"] = {"uid": 1001, "shell": "/bin/bash"}
    def docker_icc(h):
        if "/etc/docker/daemon.json" in h["json_files"]:
            h["json_files"]["/etc/docker/daemon.json"]["icc"] = True
    return [("root_login", 0.15, root_login), ("telnet", 0.10, telnet), ("ip_forward", 0.25, ip_forward),
            ("shadow", 0.10, shadow), ("auditd_down", 0.20, auditd_down), ("cbc", 0.30, cbc),
            ("guest", 0.10, guest), ("docker_icc", 0.30, docker_icc)]


def generate_fleet(baseline: dict, n: int = 20, seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    fleet = []
    for i in range(1, n + 1):
        h = json.loads(json.dumps(baseline))
        h["hostname"] = f"web-{i:03d}"
        if i % 5 == 0:  # every fifth host has no Docker at all: docker controls must be skipped
            h["files"].pop("/etc/docker/daemon.json", None)
            h["json_files"] = {}
            h["packages"].pop("docker-ce", None)
        h["_drift"] = []
        for name, prob, fn in drift_fns():
            if rng.random() < prob:
                fn(h)
                h["_drift"].append(name)
        fleet.append(h)
    return fleet


def scan_fleet(profile: Profile, fleet: list[dict], threshold: float = 90.0) -> dict:
    hosts = []
    for h in fleet:
        res = run_profile(profile, h)
        s = summarize(res)
        hosts.append({"hostname": h["hostname"], "summary": s, "failed": [r["id"] for r in res if r["status"] == "failed"]})
    failing = Counter(cid for h in hosts for cid in h["failed"])
    sev = {c.id: severity(c.impact) for c in profile.controls}
    fleet_sev: Counter = Counter()
    for cid, n in failing.items():
        fleet_sev[sev[cid]] += n
    avg = round(sum(h["summary"]["compliance_pct"] for h in hosts) / len(hosts), 1)
    return {"hosts": hosts, "fleet_average_pct": avg, "top_failing": failing.most_common(),
            "failures_by_severity": dict(fleet_sev),
            "below_threshold": [h["hostname"] for h in hosts if h["summary"]["compliance_pct"] < threshold],
            "threshold": threshold}


def render_fleet(report: dict) -> str:
    lines = [f"Fleet of {len(report['hosts'])} hosts, average compliance {report['fleet_average_pct']}%", ""]
    for h in report["hosts"]:
        s = h["summary"]
        bar = "#" * int(s["compliance_pct"] // 10)
        lines.append(f"  {h['hostname']}  {s['compliance_pct']:>5}%  {bar:<10} pass {s['passed']:>2} fail {s['failed']:>2} skip {s['skipped']:>2}  {','.join(h['failed'])}")
    lines += ["", "Most common failing controls (hosts affected):"]
    lines += [f"  {cid:<10} {n}" for cid, n in report["top_failing"][:5]]
    lines += ["", f"Failures by severity: {report['failures_by_severity']}",
              f"Below {report['threshold']}%: {', '.join(report['below_threshold']) or 'none'}"]
    return "\n".join(lines)
