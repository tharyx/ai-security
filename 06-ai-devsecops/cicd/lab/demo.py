"""Scorecard for the CI/CD lab: workflow rules, then the AI release gate.

From the repository root:
    python 06-ai-devsecops/cicd/lab/demo.py
"""

from __future__ import annotations

import copy
import shutil
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import release_gate as rg
import workflow_lint as wl

LAB = Path(__file__).parent
FIX = LAB / "fixtures"
NOW = datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc)  # fixed so the output is the same every run


def workflow_scorecard() -> None:
    def count(folder: str) -> Counter:
        found = wl.lint(wl.load(LAB / folder / "release.yml", release=True))
        found += wl.lint(wl.load(LAB / folder / "pr-eval-bot.yml"))
        return Counter(f.rule_id for f in found)

    vuln, sec = count("vulnerable"), count("secure")
    print(f"{'rule':8} {'sev':8} {'title':64} {'vulnerable':11} secure")
    print("-" * 101)
    for rule_id, (severity, title, _) in sorted(wl.RULES.items()):
        v = f"FAIL x{vuln[rule_id]}" if vuln[rule_id] else "ok"
        s = f"FAIL x{sec[rule_id]}" if sec[rule_id] else "ok"
        print(f"{rule_id:8} {severity:8} {title[:64]:64} {v:11} {s}")


def gate_scorecard(work: Path) -> None:
    good_bom, bad_bom = rg.load_json(FIX / "ai-bom.good.json"), rg.load_json(FIX / "ai-bom.bad.json")
    good_eval, bad_eval = rg.load_json(FIX / "eval-report.good.json"), rg.load_json(FIX / "eval-report.bad.json")
    model = FIX / "support-llm-v3.safetensors"
    tampered = work / model.name
    shutil.copy(model, tampered)
    data = bytearray(tampered.read_bytes())
    data[-1] ^= 0x01
    tampered.write_bytes(bytes(data))
    old_model_eval = copy.deepcopy(good_eval)
    old_model_eval["model"]["sha256"] = bad_eval["model"]["sha256"]

    cases = {
        "good": rg.evaluate(good_bom, good_eval, now=NOW, model_file=model),
        "bad BOM": rg.evaluate(bad_bom, good_eval, now=NOW),
        "bad eval": rg.evaluate(good_bom, bad_eval, now=NOW, model_file=model),
        "tampered": rg.evaluate(good_bom, good_eval, now=NOW, model_file=tampered),
        "old eval": rg.evaluate(good_bom, old_model_eval, now=NOW, model_file=model),
    }
    print(f"\n{'release gate check':56}" + "".join(f"{c:>10}" for c in cases))
    print("-" * 106)
    for check_id, title in rg.CHECKS.items():
        cells = "".join(f"{'ok' if r.results[check_id][0] else 'FAIL':>10}" for r in cases.values())
        print(f"{check_id} {title[:47]:47}{cells}")
    print(f"{'DECISION':56}" + "".join(f"{'PASS' if r.passed else 'BLOCK':>10}" for r in cases.values()))


def main() -> None:
    workflow_scorecard()
    with tempfile.TemporaryDirectory() as d:
        gate_scorecard(Path(d))
    print("\n'tampered' = one bit flipped in the weights file. 'old eval' = tests ran on a previous model.")


if __name__ == "__main__":
    main()
