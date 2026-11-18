"""Policy linter: treat the AI policy pack as code.

A policy that cannot be checked will not be followed. This linter makes sure every policy in
07-ai-governance/policies/ has the parts an auditor looks for, and that every requirement
says how it is checked.

Finding codes
    POL-01  a required section is missing
    POL-02  a required header field (owner, approver, dates...) is missing or empty
    POL-03  no numbered requirements, or a requirement ID is used twice
    POL-04  a requirement does not say how it is checked (no evidence)
    POL-05  the policy is past its next-review date
    POL-06  the framework mapping does not mention both NIST AI RMF and ISO/IEC 42001

    python 07-ai-governance/lab/policy_lint.py 07-ai-governance/policies
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

SECTIONS = ["## 1. Purpose", "## 2. Scope", "## 3. Roles", "## 4. Requirements", "## 5. Exceptions",
            "## 6. Review cycle", "## 7. Framework mapping"]
HEADER_FIELDS = ["Policy ID", "Version", "Owner", "Approved by", "Effective", "Next review"]
REQ_ROW = re.compile(r"^\|\s*([A-Z]{2,5}-\d{2})\s*\|(.*)\|(.*)\|\s*$")


@dataclass
class PolicyFinding:
    code: str
    policy: str
    message: str


def header(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|\s*$", line)
        if m and m.group(1) in HEADER_FIELDS:
            out[m.group(1)] = m.group(2)
    return out


def requirements(text: str) -> list[tuple[str, str, str]]:
    """Rows of the requirements table: (id, requirement, how we check)."""
    part = text.split("## 4. Requirements", 1)[-1].split("## 5.", 1)[0]
    return [(m.group(1), m.group(2).strip(), m.group(3).strip())
            for m in (REQ_ROW.match(line) for line in part.splitlines()) if m]


def lint_policy(name: str, text: str, as_of: date) -> list[PolicyFinding]:
    out: list[PolicyFinding] = []
    add = lambda code, msg: out.append(PolicyFinding(code, name, msg))  # noqa: E731
    for s in SECTIONS:
        if s not in text:
            add("POL-01", f"missing section '{s}'")
    h = header(text)
    for f in HEADER_FIELDS:
        if not h.get(f):
            add("POL-02", f"missing header field '{f}'")
    reqs = requirements(text)
    ids = [r[0] for r in reqs]
    if not reqs:
        add("POL-03", "no numbered requirements (use IDs such as AUP-01)")
    for dup in sorted({i for i in ids if ids.count(i) > 1}):
        add("POL-03", f"requirement ID {dup} is used more than once")
    for rid, _, check in reqs:
        if not check or check.lower() in {"-", "tbd", "n/a"}:
            add("POL-04", f"{rid} does not say how it is checked")
    try:
        nxt = date.fromisoformat(h.get("Next review", ""))
        if nxt < as_of:
            add("POL-05", f"review overdue since {nxt}")
    except ValueError:
        if h.get("Next review"):
            add("POL-02", f"'Next review' is not a date: {h['Next review']}")
    mapping = text.split("## 7. Framework mapping", 1)[-1] if "## 7. Framework mapping" in text else ""
    if "NIST AI RMF" not in mapping or "ISO/IEC 42001" not in mapping:
        add("POL-06", "mapping must cite NIST AI RMF and ISO/IEC 42001")
    return out


def lint_folder(folder: str | Path, as_of: date) -> dict[str, list[PolicyFinding]]:
    """Lint every NN-*.md policy in a folder (README.md is the index, not a policy)."""
    return {p.name: lint_policy(p.name, p.read_text(encoding="utf-8"), as_of)
            for p in sorted(Path(folder).glob("[0-9][0-9]-*.md"))}


def main() -> None:
    p = argparse.ArgumentParser(description="Lint the AI policy pack.")
    p.add_argument("folder", nargs="?", default=str(Path(__file__).resolve().parents[1] / "policies"))
    p.add_argument("--as-of", default="2026-11-15")
    args = p.parse_args()
    results = lint_folder(args.folder, date.fromisoformat(args.as_of))
    for name, findings in results.items():
        text = (Path(args.folder) / name).read_text(encoding="utf-8")
        print(f"{name:45} {len(requirements(text)):>2} requirements  "
              f"{'OK' if not findings else str(len(findings)) + ' finding(s)'}")
        for f in findings:
            print(f"{'':4}{f.code} {f.message}")


if __name__ == "__main__":
    main()
