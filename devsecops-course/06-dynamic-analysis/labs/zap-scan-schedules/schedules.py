"""ZAP Automation Framework plan generator, validator, report parser and break-build gate.

Three profiles, one per cadence:
  commit   baseline: spider + passive scan only, a few minutes, safe on every merge request
  weekly   full: spider + AJAX spider + active scan, against a staging copy
  monthly  deep: authenticated, high-strength active scan, API import, long time budget

The generated YAML follows the shape of the real ZAP Automation Framework (env / jobs).
Job and parameter names are the commonly documented ones: verify against the ZAP version you run.
Passwords are never written into the plan: they are ``${ENV_VAR}`` placeholders.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

import yaml

KNOWN_JOBS = {
    "openapi", "spider", "spiderAjax", "passiveScan-config", "passiveScan-wait",
    "activeScan", "requestor", "delay", "report", "alertFilter", "script",
}
PROFILES = ("commit", "weekly", "monthly")
RISK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}


def generate_plan(profile: str, target: str, openapi_url: str | None = None) -> dict:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; choose from {PROFILES}")
    host = urlparse(target).netloc
    ctx = {
        "name": "app",
        "urls": [target],
        "includePaths": [target.rstrip("/") + ".*"],
        "excludePaths": [target.rstrip("/") + "/logout.*"],
    }
    jobs: list = []
    if profile == "monthly":
        ctx["authentication"] = {
            "method": "json",
            "parameters": {
                "loginPageUrl": target.rstrip("/") + "/login",
                "loginRequestUrl": target.rstrip("/") + "/api/login",
                "loginRequestBody": '{"username":"{%username%}","password":"{%password%}"}',
            },
            "verification": {"method": "response", "loggedInRegex": "\\Qtoken\\E"},
        }
        ctx["sessionManagement"] = {"method": "cookie"}
        ctx["users"] = [{"name": "scan-user", "credentials": {"username": "${ZAP_SCAN_USER}", "password": "${ZAP_SCAN_PASSWORD}"}}]
    user = {"user": "scan-user"} if profile == "monthly" else {}

    if openapi_url and profile != "commit":
        jobs.append({"type": "openapi", "parameters": {"apiUrl": openapi_url, "context": "app"}})
    jobs.append({"type": "passiveScan-config", "parameters": {"scanOnlyInScope": True}})
    jobs.append({"type": "spider", "parameters": {"context": "app", "maxDuration": {"commit": 2, "weekly": 10, "monthly": 30}[profile], **user}})
    if profile != "commit":
        jobs.append({"type": "spiderAjax", "parameters": {"context": "app", "maxDuration": 10 if profile == "weekly" else 20, **user}})
    jobs.append({"type": "passiveScan-wait", "parameters": {"maxDuration": 5}})
    if profile != "commit":
        jobs.append({
            "type": "activeScan",
            "parameters": {
                "context": "app",
                "policy": "Default Policy" if profile == "weekly" else "Deep-Policy",
                "maxScanDurationInMins": 60 if profile == "weekly" else 240,
                "maxRuleDurationInMins": 5 if profile == "weekly" else 15,
                **user,
            },
        })
    jobs.append({"type": "report", "parameters": {"template": "traditional-json", "reportDir": "/zap/wrk", "reportFile": f"zap-{profile}"}})
    return {
        "env": {
            "contexts": [ctx],
            "parameters": {"failOnError": True, "failOnWarning": False, "progressToStdout": True},
        },
        "jobs": jobs,
        "_meta": {"profile": profile, "host": host},  # stripped by to_yaml; used by the validator
    }


def to_yaml(plan: dict) -> str:
    clean = {k: v for k, v in plan.items() if not k.startswith("_")}
    return yaml.safe_dump(clean, sort_keys=False)


# ---------------------------------------------------------------- validator
def validate_plan(plan: dict, allowed_hosts: tuple = ("127.0.0.1", "localhost", "staging.example.test")) -> list:
    errors: list = []
    env = plan.get("env") or {}
    ctxs = env.get("contexts") or []
    if not ctxs:
        errors.append("env.contexts is empty: no scope defined")
    names = {c.get("name") for c in ctxs}
    for c in ctxs:
        for u in c.get("urls", []):
            host = urlparse(u).hostname
            if host not in allowed_hosts:
                errors.append(f"context url host {host!r} is not in the allowed target list")
        if not c.get("urls"):
            errors.append(f"context {c.get('name')!r} has no urls")
    jobs = plan.get("jobs") or []
    types = [j.get("type") for j in jobs]
    for j in jobs:
        if j.get("type") not in KNOWN_JOBS:
            errors.append(f"unknown job type {j.get('type')!r}")
        ctx = (j.get("parameters") or {}).get("context")
        if ctx and ctx not in names:
            errors.append(f"job {j['type']} references unknown context {ctx!r}")
    if "report" not in types:
        errors.append("no report job: results would be lost")
    elif types.index("report") != len(types) - 1:
        errors.append("report job must be last")
    if "activeScan" in types and "passiveScan-wait" in types and types.index("passiveScan-wait") > types.index("activeScan"):
        errors.append("passiveScan-wait must come before activeScan")
    if "passiveScan-wait" not in types:
        errors.append("passiveScan-wait missing: passive results may be incomplete when the report is written")
    prof = (plan.get("_meta") or {}).get("profile")
    if prof == "commit" and "activeScan" in types:
        errors.append("commit profile must not run an active scan (too slow, can change data)")
    for j in jobs:
        if j.get("type") == "activeScan":
            p = j.get("parameters") or {}
            if "maxScanDurationInMins" not in p:
                errors.append("activeScan has no maxScanDurationInMins: an unbounded scan can hang the pipeline")
    for c in ctxs:
        for u in c.get("users", []):
            pw = (u.get("credentials") or {}).get("password", "")
            if pw and not str(pw).startswith("${"):
                errors.append(f"user {u.get('name')!r} has a literal password: use ${{ENV_VAR}}")
    auth_users = {u["name"] for c in ctxs for u in c.get("users", [])}
    for j in jobs:
        usr = (j.get("parameters") or {}).get("user")
        if usr and usr not in auth_users:
            errors.append(f"job {j['type']} uses user {usr!r} that is not defined")
    if prof == "monthly" and not any(c.get("authentication") for c in ctxs):
        errors.append("monthly (deep) profile must be authenticated")
    return errors


# ---------------------------------------------------------------- report parser
@dataclass(frozen=True)
class Alert:
    plugin_id: str
    name: str
    risk: str
    count: int
    uri: str = ""


def parse_zap_report(text: str) -> list:
    """Parse the ZAP ``traditional-json`` report shape: site[].alerts[]."""
    data = json.loads(text)
    out = []
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            risk = a.get("riskdesc", "Informational (x)").split(" ")[0]
            inst = a.get("instances", [])
            out.append(Alert(str(a.get("pluginid", "")), a.get("name") or a.get("alert", ""), risk, int(a.get("count", len(inst))), inst[0].get("uri", "") if inst else ""))
    return out


# ---------------------------------------------------------------- break-build rules
@dataclass
class GatePolicy:
    fail_on: str = "High"                      # fail on this risk or worse
    max_medium: int | None = None              # allow at most N medium alerts (None = unlimited)
    accepted: set = field(default_factory=set)  # plugin ids with a documented risk acceptance
    baseline: set = field(default_factory=set)  # plugin ids already known: do not fail on old debt


POLICIES = {
    "commit": GatePolicy(fail_on="High"),
    "weekly": GatePolicy(fail_on="High", max_medium=5),
    "monthly": GatePolicy(fail_on="Medium"),
}


def evaluate_gate(alerts: list, policy: GatePolicy) -> tuple:
    """Return (passed, reasons). New alerts only count when not in the baseline or accepted sets."""
    reasons: list = []
    live = [a for a in alerts if a.plugin_id not in policy.accepted]
    threshold = RISK[policy.fail_on]
    for a in live:
        if RISK.get(a.risk, 0) >= threshold and a.plugin_id not in policy.baseline:
            reasons.append(f"{a.risk} alert {a.plugin_id} '{a.name}' ({a.count} instance(s))")
    if policy.max_medium is not None:
        meds = [a for a in live if a.risk == "Medium" and a.plugin_id not in policy.baseline]
        if len(meds) > policy.max_medium:
            reasons.append(f"{len(meds)} new Medium alerts exceed the limit of {policy.max_medium}")
    return (not reasons, reasons)
