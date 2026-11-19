"""SAST as a pipeline stage: AST-based rules, SARIF-like output, severity gate, and baseline diff (fail only on NEW findings)."""

from __future__ import annotations

import ast
import hashlib
import json
import re

VULNERABLE_APP = '''\
import hashlib, subprocess, yaml, sqlite3

DB_PASSWORD = "FAKE-hardcoded-password"

def login(db, user, pw):
    q = "SELECT * FROM users WHERE name = '%s' AND pw = '%s'" % (user, pw)
    return db.execute(q)

def run_report(name):
    return subprocess.run("generate " + name, shell=True)

def load_cfg(text):
    return yaml.load(text)

def fingerprint(data):
    return hashlib.md5(data).hexdigest()

def calc(expr):
    return eval(expr)
'''

SAFE_APP = '''\
import hashlib, subprocess, yaml

def login(db, user, pw):
    return db.execute("SELECT * FROM users WHERE name = ? AND pw = ?", (user, pw))

def run_report(name):
    return subprocess.run(["generate", name], shell=False)

def load_cfg(text):
    return yaml.safe_load(text)

def fingerprint(data):
    return hashlib.sha256(data).hexdigest()
'''

RULES = {
    "SAST-001": ("critical", "eval/exec on dynamic input"),
    "SAST-002": ("high", "subprocess with shell=True"),
    "SAST-003": ("high", "SQL built with string formatting"),
    "SAST-004": ("high", "yaml.load without a safe loader"),
    "SAST-005": ("medium", "weak hash (md5/sha1)"),
    "SAST-006": ("high", "hard-coded credential"),
}
RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _call_name(node: ast.Call) -> str:
    f = node.func
    parts = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def analyze(path: str, source: str):
    out = []
    tree = ast.parse(source)

    def add(rule, node):
        sev, msg = RULES[rule]
        out.append({"ruleId": rule, "level": sev, "message": msg, "path": path, "line": node.lineno,
                    "snippet": ast.get_source_segment(source, node) or ""})

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in ("eval", "exec"):
                add("SAST-001", node)
            if name.startswith("subprocess.") and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                add("SAST-002", node)
            if name == "yaml.load" and not any(k.arg == "Loader" for k in node.keywords):
                add("SAST-004", node)
            if name in ("hashlib.md5", "hashlib.sha1"):
                add("SAST-005", node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant) \
                and isinstance(node.left.value, str) and re.search(r"(?i)\bselect\b|\binsert\b|\bupdate\b|\bdelete\b", node.left.value):
            add("SAST-003", node)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for t in node.targets:
                if isinstance(t, ast.Name) and re.search(r"(?i)(password|secret|token|api_?key)", t.id) and len(node.value.value) >= 8:
                    add("SAST-006", node)
    return out


def fingerprint(f: dict) -> str:
    return hashlib.sha256(f"{f['ruleId']}|{f['path']}|{f['snippet']}".encode()).hexdigest()[:12]  # line-independent


def to_sarif(findings) -> dict:
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "offline-sast-twin", "rules": [{"id": k, "shortDescription": {"text": v[1]}} for k, v in RULES.items()]}},
                                           "results": [{"ruleId": f["ruleId"], "level": f["level"], "message": {"text": f["message"]},
                                                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]}, "region": {"startLine": f["line"]}}}],
                                                        "partialFingerprints": {"primary": fingerprint(f)}} for f in findings]}]}


def run_stage(files: dict, fail_on: str = "high", baseline: set | None = None):
    """Pipeline stage. With a baseline (fingerprints of known findings) only NEW findings can fail the job."""
    findings = [f for p, s in files.items() for f in analyze(p, s)]
    new = [f for f in findings if fingerprint(f) not in (baseline or set())]
    blocking = [f for f in new if RANK[f["level"]] >= RANK[fail_on]]
    return {"status": "failed" if blocking else "passed", "findings": findings, "new": new, "blocking": blocking,
            "sarif": json.dumps(to_sarif(findings))}
