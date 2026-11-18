"""Check your KQL / SPL answers against the real answers computed from the sample data.

How to use:
  1. Paste events_datatable.kql above your KQL, or upload events.csv to Splunk.
  2. Answer the questions in exercises.md using the real tool.
  3. Copy answers_template.json to answers.json, fill in your answers, then run:
        python check_answers.py answers.json
  4. Stuck? `python check_answers.py --show` prints the expected answers (spoilers!).

All data is synthetic and the answers are computed here in plain Python, not by the tools.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load_minisiem():
    path = HERE.parent / "minisiem.py"
    spec = importlib.util.spec_from_file_location("minisiem_for_checker", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["minisiem_for_checker"] = mod  # dataclasses need the module registered
    spec.loader.exec_module(mod)
    return mod


QUESTIONS = {
    "Q1": "How many failed Windows logons are there in total?",
    "Q2": "Which source IP has the most failed Windows logons?",
    "Q3": "How many different accounts failed to sign in to Entra ID from 198.51.100.66?",
    "Q4": "Which user signed in successfully (Entra) from two different countries within 60 minutes?",
    "Q5": "Which member was added to the Domain Admins group?",
    "Q6": "How many Windows process-creation events run PowerShell with an encoded command (-enc or -EncodedCommand)?",
    "Q7": "On which host did an encoded PowerShell command run with WINWORD.EXE as the parent process?",
    "Q8": "Which allowed outbound destination port is NOT in the common list (53, 80, 123, 443, 8080, 8443)?",
    "Q9": "How many MB (1 MB = 1,000,000 bytes) did the firewall allow to be sent to 203.0.113.80?",
    "Q10": "How many different source IPs have failed SSH logons on Linux?",
    "Q11": "Which UTC hour (0-23) has the most failed logons across all sources?",
    "Q12": "Which account had a SUCCESSFUL Entra sign-in from the spraying IP 198.51.100.66?",
}


def expected_answers(events) -> dict:
    """Plain-Python ground truth. Written independently from the detection rules on purpose."""
    win_fail = [e for e in events if e.source == "windows" and e.action == "logon_failure"]
    ips: dict[str, int] = {}
    for e in win_fail:
        ips[e.src_ip] = ips.get(e.src_ip, 0) + 1

    ok = sorted((e for e in events if e.source == "entra" and e.action == "logon_success"), key=lambda e: (e.user, e.ts))
    travel = sorted({b.user for a, b in zip(ok, ok[1:])
                     if a.user == b.user and a.country != b.country and b.ts - a.ts <= timedelta(minutes=60)})

    enc = [e for e in events if e.action == "process_create" and e.process.lower().endswith("powershell.exe")
           and (" -enc " in e.command_line.lower() or " -encodedcommand " in e.command_line.lower())]
    common = {53, 80, 123, 443, 8080, 8443}
    rare = sorted({e.dst_port for e in events if e.action == "network_allow" and e.dst_port not in common})
    by_hour: dict[int, int] = {}
    for e in events:
        if e.action == "logon_failure":
            by_hour[e.ts.hour] = by_hour.get(e.ts.hour, 0) + 1

    return {
        "Q1": len(win_fail),
        "Q2": max(ips, key=lambda k: ips[k]),
        "Q3": len({e.user for e in events if e.source == "entra" and e.action == "logon_failure" and e.src_ip == "198.51.100.66"}),
        "Q4": travel[0] if len(travel) == 1 else travel,
        "Q5": next(e.member for e in events if e.action == "group_add" and e.group == "Domain Admins"),
        "Q6": len(enc),
        "Q7": next(e.host for e in enc if e.parent_process.lower().endswith("winword.exe")),
        "Q8": rare[0] if len(rare) == 1 else rare,
        "Q9": round(sum(e.bytes_out for e in events if e.action == "network_allow" and e.dst_ip == "203.0.113.80") / 1_000_000),
        "Q10": len({e.src_ip for e in events if e.source == "linux" and e.action == "logon_failure"}),
        "Q11": max(by_hour, key=lambda h: by_hour[h]),
        "Q12": next(e.user for e in events if e.source == "entra" and e.action == "logon_success" and e.src_ip == "198.51.100.66"),
    }


def _norm(v):
    if isinstance(v, str):
        v = v.strip().lower()
        try:
            return int(v)
        except ValueError:
            return v
    return v


def check(answers: dict, expected: dict) -> dict[str, bool | None]:
    """True = correct, False = wrong, None = not answered."""
    result = {}
    for q, want in expected.items():
        got = answers.get(q)
        result[q] = None if got in (None, "") else _norm(got) == _norm(want)
    return result


def main(argv: list[str]) -> int:
    expected = expected_answers(_load_minisiem().ingest())
    if argv and argv[0] == "--show":
        for q, v in expected.items():
            print(f"{q}: {v}   ({QUESTIONS[q]})")
        return 0
    path = Path(argv[0]) if argv else HERE / "answers.json"
    if not path.exists():
        print(f"No answers file at {path}. Copy answers_template.json to answers.json and fill it in.")
        return 2
    answers = json.loads(path.read_text(encoding="utf-8"))
    result = check(answers, expected)
    for q, ok in result.items():
        mark = {True: "PASS", False: "FAIL", None: "----"}[ok]
        print(f"{q:4} {mark}  {QUESTIONS[q]}")
    score = sum(1 for v in result.values() if v)
    print(f"\nScore: {score}/{len(result)}")
    return 0 if score == len(result) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
