"""CI gate: read a scanner JSONL report and fail the build when there are hits.

Usage (exit code 0 = pass, 1 = fail, 2 = bad input):
    python ci_gate.py <run>.report.jsonl [--max-hits 0] [--min-pass-rate 1.0]

The same pattern works for real garak reports: parse the ``eval`` entries, compare with a
threshold, exit non-zero. Field names in real garak reports differ by version; check yours.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def evaluate(report: Path, max_hits: int = 0, min_pass_rate: float = 1.0) -> tuple[int, list[str]]:
    try:
        lines = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError) as exc:
        return 2, [f"cannot read report: {exc}"]
    evals = [e for e in lines if e.get("entry_type") == "eval"]
    if not evals:
        return 2, ["no eval entries: the scan did not finish, fail closed"]
    hits = sum(e["total"] - e["passed"] for e in evals)
    msgs, failed = [], hits > max_hits
    for e in evals:
        rate = e["passed"] / e["total"] if e["total"] else 0.0
        bad = rate < min_pass_rate
        failed |= bad
        msgs.append(f"{'FAIL' if bad else 'ok  '} {e['probe']:<24} pass {rate:6.1%}  hits {e['total'] - e['passed']}")
    msgs.append(f"total hits {hits} (allowed {max_hits}) -> {'BUILD FAILED' if failed else 'BUILD PASSED'}")
    return (1 if failed else 0), msgs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("report", type=Path)
    ap.add_argument("--max-hits", type=int, default=0)
    ap.add_argument("--min-pass-rate", type=float, default=1.0)
    args = ap.parse_args(argv)
    code, msgs = evaluate(args.report, args.max_hits, args.min_pass_rate)
    print("\n".join(msgs))
    return code


if __name__ == "__main__":
    sys.exit(main())
