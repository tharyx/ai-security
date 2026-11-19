import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import triage as t  # noqa: E402

SC = {k: v for k, v in t.load(HERE / "fixtures/scenarios.json").items() if not k.startswith("_")}
KEY = t.load(HERE / "fixtures/answer_key.json")

print("1. Baseline bot vs answer key")
print(f"   {'id':4} {'bot mode':14} {'key mode':14} {'bot stage':>9} {'key stage':>9}  recommended (rule = key?)")
for sid, s in SC.items():
    k = KEY[sid]
    rec = t.recommend_mode(s["stakes"], s["relationship"], s["urgency"])
    print(f"   {sid:4} {str(t.classify_mode(s['text'])):14} {k['mode_used']:14} {str(t.glasl_stage(s['text'])):>9} "
          f"{k['stage']:>9}  {rec} ({'yes' if rec == k['recommended'] else 'NO'}) [{t.LEVELS[k['stage']]}]")

print("\n2. Scoring an example learner's answers")
mine = {k: v for k, v in t.load(HERE / "fixtures/my_answers_example.json").items() if not k.startswith("_")}
pts, total, fb = t.score_answers(mine, KEY)
print(f"   score {pts}/{total} (stage within 1 counts as correct)")
for line in fb:
    print("   -", line)

print("\n3. Conflicting priorities: one sprint, five asks")
items = [
    {"name": "Fix BOLA on /orders/{id} (internet-facing)", "risk": t.risk_score(4, 5, True, False), "value": 8},
    {"name": "Upgrade library on KEV list", "risk": t.risk_score(4, 4, True, True), "value": 3},
    {"name": "DPDP consent logging", "regulatory": True, "risk": 9, "value": 5},
    {"name": "New loyalty-points feature", "risk": 0, "value": 9},
    {"name": "Dark mode for admin UI", "risk": 0, "value": 0},
]
for it in items:
    print(f"   risk {it.get('risk', 0):>2}  {it['name']}")
print("   MoSCoW:", t.moscow(items))
print("   RICE loyalty feature:", t.rice(reach=5000, impact=2, confidence=0.8, effort=4),
      "| RICE dark mode:", t.rice(reach=40, impact=0.5, confidence=0.9, effort=1))
