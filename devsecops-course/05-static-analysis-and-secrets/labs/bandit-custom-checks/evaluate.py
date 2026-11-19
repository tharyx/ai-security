"""Score scanners against ground truth written in the fixtures (`# expect: <category>` on def lines).

Granularity is the FUNCTION: a finding is a true positive when the function that contains it is marked
with the finding's category. This keeps the comparison fair between tools that report on different lines.
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path

from aisec_lab import load_lab_module

bl = load_lab_module(__file__, "bandit_lite")
cc = load_lab_module(__file__, "corp_checks")

CATEGORY = {"B608": "sqli", "E901": "sqli", "NAIVE-LOG": "secret-log", "E903": "secret-log",
            "E902": "timeout", "E904": "authz"}
EXPECT = re.compile(r"#\s*expect:\s*([\w-]+)")
NAIVE_LOG = re.compile(r"(logger|logging|log)\.\w+\(.*(password|secret|token|key)", re.I)


def ground_truth(root: Path) -> set[tuple[str, str, str]]:
    """{(file, function, category)}"""
    truth = set()
    for p in sorted(Path(root).rglob("*.py")):
        lines = p.read_text(encoding="utf-8").splitlines()
        for node in ast.walk(ast.parse("\n".join(lines))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                m = EXPECT.search(lines[node.lineno - 1])
                if m:
                    truth.add((p.relative_to(root).as_posix(), node.name, m.group(1)))
    return truth


def function_at(root: Path, file: str, lineno: int) -> str:
    tree = ast.parse((Path(root) / file).read_text(encoding="utf-8"))
    best = ""
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.lineno <= lineno <= (n.end_lineno or n.lineno):
            best = n.name
    return best


def naive_log_findings(root: Path) -> list:
    """What a grep-style rule does: any logging line that mentions a secret-ish WORD anywhere."""
    out = []
    for p in sorted(Path(root).rglob("*.py")):
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if NAIVE_LOG.search(line):
                out.append(bl.Issue(bl.MEDIUM, bl.LOW, 532, "log line mentions a secret word", "NAIVE-LOG",
                                    n, p.relative_to(root).as_posix(), line.strip()))
    return out


def score(root: Path, issues: list) -> dict[str, dict]:
    truth = ground_truth(root)
    found = {(i.filename, function_at(root, i.filename, i.lineno), CATEGORY[i.test_id])
             for i in issues if i.test_id in CATEGORY}
    cats = {c for _, _, c in truth} | {c for _, _, c in found}
    out = {}
    for c in sorted(cats):
        t = {x for x in truth if x[2] == c}
        f = {x for x in found if x[2] == c}
        tp, fp, fn = len(t & f), len(f - t), len(t - f)
        out[c] = {"tp": tp, "fp": fp, "fn": fn,
                  "precision": round(tp / (tp + fp), 2) if tp + fp else 1.0,
                  "recall": round(tp / (tp + fn), 2) if tp + fn else 1.0}
    return out


def baseline_issues(root: Path) -> list:
    return bl.scan_path(root, [bl.sql_string_building]) + naive_log_findings(root)


def custom_issues(root: Path) -> list:
    return bl.scan_path(root, bl.load_checks(cc))


def summarize(scores: dict[str, dict]) -> dict[str, int]:
    agg = defaultdict(int)
    for s in scores.values():
        for k in ("tp", "fp", "fn"):
            agg[k] += s[k]
    return dict(agg)
