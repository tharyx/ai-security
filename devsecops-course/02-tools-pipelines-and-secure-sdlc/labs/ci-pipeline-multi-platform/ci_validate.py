"""Validate that the SAME secure pipeline, written for five CI systems, still has its gates.

Checks per file:
  stages      required stages present and in a sane order
  pinning     GitHub actions pinned to a 40-char commit SHA; container images pinned (no :latest)
  secrets     no token-shaped strings and no literal password/token/key assignments in the YAML
  privilege   least-privilege tokens (permissions, scoped credentials, no docker.sock/privileged)

Offline and pure Python (PyYAML for YAML, regex for the Jenkinsfile). This is a teaching linter,
not a replacement for tools like actionlint, zizmor or the CI system's own validation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

CANON = ["secrets-scan", "sca", "sast", "build", "image-scan", "dast", "deploy"]

# classification of a step by the tool it runs (first match wins, specific tools first)
PATTERNS = [
    ("secrets-scan", r"gitleaks|trufflehog|detect-secrets"),
    ("sca", r"npm audit|osv-scanner|pip-audit|dependency-check|snyk test|\bretire(js)?\b"),
    ("sast", r"semgrep|\bbandit\b|spotbugs|brakeman|codeql"),
    ("image-scan", r"trivy[ -]action|trivy image|\bgrype\b"),
    ("dast", r"zap-baseline|zap-full-scan|zap-api-scan|action-baseline|action-full-scan"),
    ("deploy", r"deploy\.sh|kubectl apply|helm (upgrade|install)|ansible-playbook"),
    ("build", r"docker build|kaniko/executor|docker buildx|npm run build"),
]
ORDER_RULES = [
    ("secrets-scan", "build"), ("sca", "build"), ("sast", "build"),
    ("build", "image-scan"), ("build", "dast"),
    ("image-scan", "deploy"), ("dast", "deploy"),
]

TOKEN_PATTERNS = {
    "github token": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "aws access key id": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "slack token": r"xox[baprs]-[A-Za-z0-9-]{10,}",
    "gitlab token": r"glpat-[A-Za-z0-9_-]{20,}",
    "private key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
}
ASSIGN = re.compile(
    r"(?im)\b([A-Z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[A-Z0-9_.-]*)"
    r"[ \t]*[:=][ \t]*[\"']?([^\s\"'#]+)")
SAFE_VALUE_PREFIX = ("$", "{{", "<", "credentials(", "secrets.", "env.", "vars.")
SAFE_VALUES = {"read", "write", "none", "true", "false", "null", "~"}


@dataclass
class Issue:
    check: str  # stages | pinning | secrets | privilege
    message: str
    severity: str = "error"


@dataclass
class Step:
    unit: str  # job or stage name
    text: str


@dataclass
class Report:
    platform: str
    stages_found: list
    issues: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not [i for i in self.issues if i.severity == "error"]

    def by_check(self, check):
        return [i for i in self.issues if i.check == check]


# ------------------------------------------------------------------ platform detection


def detect_platform(name: str, text: str) -> str:
    low = name.lower()
    if "jenkinsfile" in low or re.search(r"^\s*pipeline\s*\{", text, re.M):
        return "jenkins"
    if "gitlab" in low:
        return "gitlab"
    if "travis" in low:
        return "travis"
    if "circle" in low:
        return "circleci"
    if "github" in low or "workflow" in low:
        return "github"
    doc = yaml.safe_load(text) or {}
    if isinstance(doc, dict):
        jobs = doc.get("jobs")
        if isinstance(jobs, dict) and any(isinstance(j, dict) and "runs-on" in j for j in jobs.values()):
            return "github"
        if "workflows" in doc:
            return "circleci"
        if "language" in doc:
            return "travis"
        if "stages" in doc:
            return "gitlab"
    raise ValueError("cannot detect CI platform")


# ------------------------------------------------------------------ step extraction


def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def steps_gitlab(doc) -> list:
    stages = doc.get("stages", [])
    jobs = [(k, v) for k, v in doc.items() if isinstance(v, dict) and "script" in v and not k.startswith(".")]
    jobs.sort(key=lambda kv: stages.index(kv[1].get("stage", "test")) if kv[1].get("stage", "test") in stages else 99)
    out = []
    for name, job in jobs:
        for line in _as_list(job.get("before_script")) + _as_list(job.get("script")):
            out.append(Step(name, str(line)))
    return out


def steps_github(doc) -> list:
    jobs = doc.get("jobs", {})
    done, order = set(), []
    pending = list(jobs)
    while pending:  # simple topological sort on `needs`
        progressed = False
        for j in list(pending):
            if all(n in done for n in _as_list(jobs[j].get("needs"))):
                order.append(j)
                done.add(j)
                pending.remove(j)
                progressed = True
        if not progressed:
            order += pending
            break
    out = []
    for name in order:
        for s in jobs[name].get("steps", []) or []:
            text = " ".join(str(s.get(k, "")) for k in ("name", "run", "uses"))
            out.append(Step(name, text))
    return out


def steps_circleci(doc) -> list:
    wf = next(iter(doc.get("workflows", {}).values() if isinstance(doc.get("workflows"), dict) else []), {})
    names = []
    for item in wf.get("jobs", []) if isinstance(wf, dict) else []:
        names.append(item if isinstance(item, str) else next(iter(item)))
    out = []
    for name in names:
        job = doc.get("jobs", {}).get(name, {})
        for s in job.get("steps", []) or []:
            if isinstance(s, dict) and "run" in s:
                run = s["run"]
                out.append(Step(name, run if isinstance(run, str) else str(run.get("command", ""))))
    return out


def steps_travis(doc) -> list:
    out = []
    for item in (doc.get("jobs") or {}).get("include", []) or []:
        unit = str(item.get("stage", "job"))
        for line in _as_list(item.get("script")):
            out.append(Step(unit, str(line)))
    for line in _as_list(doc.get("script")):
        out.append(Step("script", str(line)))
    return out


def _strip_groovy_comments(text: str) -> str:
    return re.sub(r"(?m)(^|\s)//.*$", "", text)


def jenkins_stages(text: str) -> list:
    """Return [(stage name, block text)] by matching braces after stage('name')."""
    text = _strip_groovy_comments(text)
    out = []
    for m in re.finditer(r"stage\s*\(\s*['\"]([^'\"]+)['\"]\s*\)\s*\{", text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        out.append((m.group(1), text[m.end():i - 1]))
    return out


def steps_jenkins(text: str) -> list:
    return [Step(name, block) for name, block in jenkins_stages(text)]


def classify(text: str):
    low = text.lower()
    for canon, pat in PATTERNS:
        if re.search(pat, low):
            return canon
    return None


# ------------------------------------------------------------------ checks


def check_stages(steps: list) -> tuple:
    found = {}
    for i, s in enumerate(steps):
        c = classify(s.text)
        if c and c not in found:
            found[c] = i
    issues = [Issue("stages", f"required stage '{c}' not found") for c in CANON if c not in found]
    for a, b in ORDER_RULES:
        if a in found and b in found and found[a] > found[b]:
            issues.append(Issue("stages", f"'{a}' must run before '{b}'"))
    return sorted(found, key=found.get), issues


IMAGE_RES = [re.compile(r"(?m)^[ \t]*-?[ \t]*image:[ \t]*[\"']?([^\s\"'#]+)"),
             re.compile(r"(?m)^[ \t]*image:[ \t]*\n[ \t]+name:[ \t]*[\"']?([^\s\"'#]+)"),
             re.compile(r"\bimage\s+['\"]([^'\"]+)['\"]")]


def image_pinned(ref: str) -> bool:
    if "$" in ref or "<<" in ref or "{{" in ref:
        return True  # built from a variable: cannot judge statically
    if "@sha256:" in ref:
        return True
    last = ref.rsplit("/", 1)[-1]
    return ":" in last and not last.endswith(":latest")


def check_pinning(platform: str, text: str, doc) -> list:
    issues = []
    if platform == "github":
        def visit(uses, where):
            if uses.startswith("./"):
                return
            if uses.startswith("docker://"):
                if not image_pinned(uses[len("docker://"):]):
                    issues.append(Issue("pinning", f"{where}: image '{uses}' is not pinned"))
                return
            ref = uses.rsplit("@", 1)[-1] if "@" in uses else ""
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                issues.append(Issue("pinning", f"{where}: '{uses}' is not pinned to a commit SHA"))
        for jn, job in (doc.get("jobs") or {}).items():
            if "uses" in job:
                visit(job["uses"], jn)
            for s in job.get("steps", []) or []:
                if "uses" in s:
                    visit(s["uses"], jn)
    for rx in IMAGE_RES:
        for ref in rx.findall(text):
            if not image_pinned(ref):
                issues.append(Issue("pinning", f"container image '{ref}' is not pinned (no tag or :latest)"))
    if platform == "circleci":
        for name, ver in re.findall(r"(?m)^\s+\w[\w-]*:\s*([\w./-]+)@([\w.]+)\s*$", text):
            if not re.fullmatch(r"\d+\.\d+\.\d+", ver):
                issues.append(Issue("pinning", f"orb '{name}@{ver}' must use an exact version"))
    return issues


def check_secrets(text: str) -> list:
    issues = []
    for label, pat in TOKEN_PATTERNS.items():
        if re.search(pat, text):
            issues.append(Issue("secrets", f"looks like a {label} in the file"))
    for m in ASSIGN.finditer(text):
        key, value = m.group(1), m.group(2)
        if key.lower() in ("id-token", "persist-credentials") or value.lower() in SAFE_VALUES:
            continue
        if value.startswith(SAFE_VALUE_PREFIX) or len(value) < 4:
            continue
        issues.append(Issue("secrets", f"literal value assigned to '{key}'"))
    return issues


def check_privilege(platform: str, text: str, doc, steps: list) -> list:
    issues = []
    if "docker.sock" in text:
        issues.append(Issue("privilege", "mounts docker.sock (root on the runner)"))
    if re.search(r"--privileged|privileged:\s*true", text):
        issues.append(Issue("privilege", "runs a privileged container"))
    if platform == "github":
        perms = doc.get("permissions")
        if perms is None:
            issues.append(Issue("privilege", "no top-level 'permissions:' (token may default to write)"))
        elif perms == "write-all":
            issues.append(Issue("privilege", "permissions: write-all"))
        elif isinstance(perms, dict):
            for k, v in perms.items():
                if v == "write":
                    issues.append(Issue("privilege", f"top-level permission '{k}: write'"))
        elif perms == "read-all":
            issues.append(Issue("privilege", "read-all is broader than needed", "warning"))
        for jn, job in (doc.get("jobs") or {}).items():
            jp = job.get("permissions")
            if jp == "write-all":
                issues.append(Issue("privilege", f"job '{jn}': permissions: write-all"))
            if isinstance(jp, dict):
                for k, v in jp.items():
                    if v == "write" and k != "id-token":
                        issues.append(Issue("privilege", f"job '{jn}': '{k}: write'"))
            for s in job.get("steps", []) or []:
                if str(s.get("uses", "")).startswith("actions/checkout") and \
                        (s.get("with") or {}).get("persist-credentials") is not False:
                    issues.append(Issue("privilege", f"job '{jn}': checkout keeps the token (persist-credentials)",
                                        "warning"))
    elif platform == "gitlab":
        if re.search(r"GITLAB_(PERSONAL_)?TOKEN|PRIVATE-TOKEN|PERSONAL_ACCESS_TOKEN", text):
            issues.append(Issue("privilege", "uses a personal access token instead of CI_JOB_TOKEN / id_tokens"))
        dep = doc.get("deploy")
        if isinstance(dep, dict) and not re.search(r"CI_DEFAULT_BRANCH|main", str(dep.get("rules", dep.get("only", "")))):
            issues.append(Issue("privilege", "deploy job is not limited to the default branch", "warning"))
    elif platform == "jenkins":
        if re.search(r"agent\s+any\b", text):
            issues.append(Issue("privilege", "'agent any' lets every stage run anywhere", "warning"))
        for name, block in jenkins_stages(text):
            if re.search(r"withCredentials|credentials\s*\(", block) and "deploy" not in name.lower():
                issues.append(Issue("privilege", f"stage '{name}' uses credentials; keep them in the deploy stage"))
    elif platform == "circleci":
        wf = next(iter((doc.get("workflows") or {}).values()), {})
        for item in wf.get("jobs", []):
            if isinstance(item, dict):
                name, opts = next(iter(item.items()))
                if name == "deploy" and not (opts or {}).get("context"):
                    issues.append(Issue("privilege", "deploy job has no restricted 'context'"))
                if name == "deploy" and "filters" not in (opts or {}):
                    issues.append(Issue("privilege", "deploy job has no branch filter", "warning"))
    elif platform == "travis":
        for item in (doc.get("jobs") or {}).get("include", []) or []:
            if item.get("stage") == "deploy" and "if" not in item:
                issues.append(Issue("privilege", "deploy job has no 'if: branch = main' condition", "warning"))
    return issues


# ------------------------------------------------------------------ entry points


def validate_text(name: str, text: str) -> Report:
    platform = detect_platform(name, text)
    doc = None
    if platform == "jenkins":
        steps = steps_jenkins(text)
    else:
        doc = yaml.safe_load(text) or {}
        steps = {"gitlab": steps_gitlab, "github": steps_github,
                 "circleci": steps_circleci, "travis": steps_travis}[platform](doc)
    found, issues = check_stages(steps)
    issues += check_pinning(platform, text, doc or {})
    issues += check_secrets(text)
    issues += check_privilege(platform, text, doc or {}, steps)
    return Report(platform, found, issues)


def validate_file(path) -> Report:
    p = Path(path)
    return validate_text(p.name, p.read_text(encoding="utf-8"))
