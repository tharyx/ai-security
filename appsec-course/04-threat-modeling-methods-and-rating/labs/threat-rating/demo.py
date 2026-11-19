"""Rate the same threat four ways: OWASP Risk Rating, DREAD, a bug bar and an RRA."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import rating as r  # noqa: E402

factors = {
    "skill_level": 6, "motive": 7, "opportunity": 9, "size": 9,
    "ease_of_discovery": 7, "ease_of_exploit": 5, "awareness": 6, "intrusion_detection": 8,
    "loss_of_confidentiality": 6, "loss_of_integrity": 5, "loss_of_availability": 1, "loss_of_accountability": 7,
    "financial_damage": 3, "reputation_damage": 5, "non_compliance": 5, "privacy_violation": 7,
}
print("=== OWASP Risk Rating: predictable password-reset token ===")
print("before fix:", r.owasp_risk(factors))
fixed = dict(factors, ease_of_discovery=1, ease_of_exploit=1, awareness=4, intrusion_detection=3)
print("after fix: ", r.owasp_risk(fixed))
print("technical impact only:", r.owasp_risk(factors, business_known=False)["impact"])

print("\n=== DREAD: same threat, two raters ===")
a = {"damage": 8, "reproducibility": 9, "exploitability": 7, "affected_users": 8, "discoverability": 9}
b = {"damage": 5, "reproducibility": 4, "exploitability": 4, "affected_users": 3, "discoverability": 2}
print("rater A:", r.dread(a), " rater B:", r.dread(b), " spread:", r.rater_spread([a, b]))

print("\n=== Bug bar ===")
cases = [("Elevation of privilege", "remote_anonymous", {}),
         ("Information disclosure", "remote_authenticated", {"sensitive_data": True}),
         ("Denial of service", "remote_anonymous", {"persistent": False}),
         ("Spoofing", "remote_anonymous", {"user_interaction": True})]
for effect, scope, kw in cases:
    sev = r.bug_bar(effect, scope, **kw)
    print(f"  {effect:24} {scope:21} {kw!s:28} -> {sev:9} blocker={r.release_blocker(sev)}")

print("\n=== Rapid Risk Assessment (draft) ===")
rra = json.loads((HERE / "fixtures" / "rra_reset_service.json").read_text(encoding="utf-8"))
print(r.rra_report(rra))
