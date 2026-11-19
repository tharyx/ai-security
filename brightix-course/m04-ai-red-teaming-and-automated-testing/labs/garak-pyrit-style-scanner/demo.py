"""Demo: garak-shaped scan, PyRIT-shaped single-turn + Crescendo-style runs, and a CI gate.

Run from the repo root:
    .venv/Scripts/python brightix-course/m04-ai-red-teaming-and-automated-testing/labs/garak-pyrit-style-scanner/demo.py
"""

from __future__ import annotations

import tempfile

from aisec_lab import load_lab_module

T = load_lab_module(__file__, "targets")
S = load_lab_module(__file__, "scanner")
O = load_lab_module(__file__, "orchestrator")
G = load_lab_module(__file__, "ci_gate")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        print("== 1. garak-shaped scan: 4 probes x (plain + 3 buffs) ==")
        for name in ("naive", "guarded"):
            res = S.run_scan(T.make_app(name), list(S.PROBES), ["base64", "rot13", "leet"], tmp, run_id=f"demo-{name}")
            print(f"\n[{name}] total hits: {res.total_hits}")
            print("\n".join(S.summary_lines(res)))
            code, msgs = G.evaluate(res.report_path)
            print(f"CI gate exit code: {code} ({msgs[-1]})")
        first_hit = open(f"{tmp}/demo-naive.hitlog.jsonl", encoding="utf-8").readline()
        print("\nFirst hit-log line (naive):", first_hit[:220].strip(), "...")

    print("\n== 2. PyRIT-shaped single turn: one jailbreak prompt through converters ==")
    prompt = S.PROBES["jailbreak.LabRoleplay"].prompts[0]
    for name in ("naive", "guarded"):
        for conv in ([], [O.Base64Converter()], [O.ROT13Converter()], [O.LeetspeakConverter()]):
            mem = O.Memory()
            orch = O.PromptSendingOrchestrator(O.AppTarget(T.make_app(name)), [O.SubstringScorer("UNSAFE_CONTENT"),
                                               O.RefusalScorer()], mem, conv)
            r = orch.send_prompts([prompt])[0]
            label = "+".join(c.name for c in conv) or "none"
            print(f"  {name:<8} converter={label:<10} achieved={r['achieved']!s:<5} reply={r['reply'][:60]!r}")

    print("\n== 3. Crescendo-style multi-turn escalation (max 6 turns, backtracking) ==")
    for name in ("naive", "guarded"):
        mem = O.Memory()
        orch = O.CrescendoOrchestrator(O.AppTarget(T.make_app(name)), O.RuleJudgeScorer(), mem, max_turns=6)
        r = orch.run()
        print(f"[{name}] achieved={r['achieved']} turns={r['turns_used']} backtracks={r['backtracks']} stop={r['stop_reason']}")
        for turn, text, value, why in r["trace"]:
            print(f"   turn {turn}: judge={value:.0f} ({why}) <- {text!r}")
        rows = mem.query("SELECT COUNT(*), SUM(kept=0) FROM messages")
        print(f"   memory: {rows[0][0]} messages stored, {rows[0][1]} marked as backtracked")


if __name__ == "__main__":
    main()
