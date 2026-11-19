"""Audit serverless function fixtures: env-var secrets, layers/deps, execution roles. Offline."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

SECRET_NAME = re.compile(r"(pass(word)?|secret|token|api[_-]?key|connection[_-]?string|private[_-]?key)", re.I)
SECRET_VALUE = [re.compile(p) for p in (r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{20,}", r"AccountKey=[A-Za-z0-9+/=]{16,}")]
REFERENCE = re.compile(r"^(arn:aws:secretsmanager|arn:aws:ssm|projects/.+/secrets/|https://.+\.vault\.)")
PRIV_ESC_ACTIONS = ("iam:passrole", "iam:createpolicyversion", "iam:attachrolepolicy", "lambda:updatefunctioncode", "iam:putrolepolicy")
BROAD_ROLES = ("roles/editor", "roles/owner", "contributor", "owner")
SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    function: str
    detail: str


def _ver(v: str):
    return tuple(int(p) for p in re.findall(r"\d+", v))


def entropy(s: str) -> float:
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def audit_env(fn):
    out = []
    for k, v in fn.get("env", {}).items():
        if REFERENCE.match(v):
            continue  # a pointer to a secret manager is the good pattern
        if SECRET_NAME.search(k) or any(p.search(v) for p in SECRET_VALUE):
            out.append(Finding("ENV-SECRET", "high", fn["name"], f"{k} looks like a secret stored in an environment variable"))
    return out


def audit_layers(fn, trusted):
    out = []
    for l in fn.get("layers", []):
        if l["account"] not in trusted:
            out.append(Finding("LAYER-THIRD-PARTY", "high", fn["name"], f"layer {l['name']} comes from untrusted account {l['account']}"))
        if not isinstance(l["version"], int):
            out.append(Finding("LAYER-UNPINNED", "medium", fn["name"], f"layer {l['name']} version '{l['version']}' is not pinned"))
    return out


def audit_deps(fn, advisories, malicious):
    out = []
    for d in fn.get("deps", []):
        if d["name"] in malicious:
            out.append(Finding("DEP-MALICIOUS", "critical", fn["name"], f"{d['name']} is on the known-malicious list"))
        adv = advisories.get(d["name"])
        if adv and _ver(d["version"]) < _ver(adv["vulnerable_below"]):
            out.append(Finding("DEP-VULNERABLE", "high", fn["name"], f"{d['name']}@{d['version']} < {adv['vulnerable_below']} ({adv['id']})"))
        if not d.get("hash"):
            out.append(Finding("DEP-NO-HASH", "low", fn["name"], f"{d['name']} has no pinned hash in the build"))
    return out


def audit_role(fn):
    out = []
    for p in fn["role"]["policies"]:
        acts = [a.lower() for a in p["Action"]]
        res = p.get("Resource", "")
        if any(a in ("*", "*:*") or a.endswith(":*") for a in acts) and res == "*":
            out.append(Finding("ROLE-WILDCARD", "high", fn["name"], f"{p['Action']} on every resource"))
        if any(a in BROAD_ROLES for a in acts):
            out.append(Finding("ROLE-BROAD-BUILTIN", "high", fn["name"], f"broad built-in role {p['Action']}"))
        if any(a in PRIV_ESC_ACTIONS for a in acts) and res == "*":
            out.append(Finding("ROLE-PRIVESC", "critical", fn["name"], "can pass or change roles on any resource: privilege-escalation path"))
    return out


def audit_exposure(fn):
    if fn.get("url_auth") in ("NONE", "allUsers"):
        return [Finding("URL-NO-AUTH", "high", fn["name"], "function URL/trigger is callable without authentication")]
    return []


def audit(doc):
    out = []
    for fn in doc["functions"]:
        out += audit_env(fn) + audit_layers(fn, set(doc["trusted_layer_accounts"]))
        out += audit_deps(fn, doc["advisories"], set(doc["known_malicious"]))
        out += audit_role(fn) + audit_exposure(fn)
    return sorted(out, key=lambda f: (SEV[f.severity], f.function, f.rule))


def blast_radius(fn) -> str:
    """One-line summary used by the demo: what can a code-execution bug in this function reach?"""
    f = audit_role(fn)
    if any(x.rule == "ROLE-PRIVESC" for x in f):
        return "may escalate to other roles"
    if f:
        return "broad data/resource access"
    return "scoped to its own resources"


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))
