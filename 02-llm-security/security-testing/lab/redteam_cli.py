"""CI entry point: run the attack suite against a target and fail the build if the gate fails.

From the repository root:
    python 02-llm-security/security-testing/lab/redteam_cli.py --target secure --runs 10
    python 02-llm-security/security-testing/lab/redteam_cli.py --target vulnerable --report report.md

Exit codes (what CI looks at):
    0  gate passed
    1  gate failed (attack success rate or false-refusal rate above the limit)
    2  the suite file is invalid (a broken test suite must never "pass")
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from harness import load_suite, render_report, evaluate_gate, run_suite
from limits import Limits
from pydantic import ValidationError
from secure_target import SecureSupportBot
from stochastic_model import StochasticMockLLM
from vulnerable_target import VulnerableSupportBot

from aisec_lab import get_llm

HERE = Path(__file__).resolve().parent


def make_llm(seed: int):
    if os.getenv("AISEC_LLM_BACKEND", "mock") == "mock":
        return StochasticMockLLM(seed=seed)
    return get_llm()  # a real model: non-deterministic for real


def factory(target: str):
    if target == "vulnerable":
        return lambda seed: VulnerableSupportBot(make_llm(seed))
    if target == "secure":
        return lambda seed: SecureSupportBot(make_llm(seed), limits=Limits())
    raise ValueError(target)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LLM red-team gate")
    parser.add_argument("--suite", default=str(HERE / "attack_suite.yaml"))
    parser.add_argument("--target", choices=["vulnerable", "secure"], default="secure")
    parser.add_argument("--runs", type=int, default=10, help="runs per case (N)")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--report", help="also write the markdown report to this file")
    args = parser.parse_args(argv)

    try:
        suite = load_suite(args.suite)
    except (ValidationError, OSError, ValueError) as exc:
        print(f"invalid suite: {exc}", file=sys.stderr)
        return 2

    result = run_suite(suite, factory(args.target), runs=args.runs, seed=args.seed,
                       target_name=args.target)
    report = render_report(result)
    print(report)
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")

    failures = evaluate_gate(result)
    print("GATE:", "PASS" if not failures else "FAIL - " + "; ".join(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
