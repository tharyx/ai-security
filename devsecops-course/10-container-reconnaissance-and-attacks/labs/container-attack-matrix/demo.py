import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import matrix as mx

print("Container Attack Matrix (teaching summary):")
for t in mx.TACTICS:
    print(f"  {t:<21} {len(mx.TECHNIQUES[t])} techniques, e.g. {mx.TECHNIQUES[t][0]}")
print(f"\nCCSE 3 topics: {len(mx.CCSE3_TOPICS)}; hands-on exercises: {len(mx.CCSE3_EXERCISES)}; topics without a lab: {len(mx.missing_labs())}")
print("\nTopic -> lab (first 6):")
for topic, kind, lab, tactics in mx.CCSE3_TOPICS[:6]:
    print(f"  {topic:<48} {kind}:{lab:<32} {', '.join(tactics)}")
found = ["UNAUTH-API", "ESC-SOCK", "SECRETS-IN-LAYER", "NO-LIMITS", "FLAT-NET", "EVT-EXEC"]
print("\nFindings from an assessment:", found)
for t, ids in mx.coverage(found).items():
    if ids:
        print(f"  {t:<21} {ids}")
print(mx.kill_chain(found))
