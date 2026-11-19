"""Play one scripted round of the threat card game. Offline, fictional system."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import threat_cards as g  # noqa: E402

players = ["Asha", "Ben", "Chen"]
print("Hands (seed 7):", g.deal(players, seed=7))
round_ = [
    g.Play("Asha", "T1", "F1", "Order total altered between browser and web tier", "TLS + recompute price server-side"),
    g.Play("Ben", "S1", "db", "Someone pretends to be the database", "mTLS"),
    g.Play("Chen", "R2", "audit_log", "Support admin deletes own refund entries", "Append-only storage, separate log admin"),
    g.Play("Asha", "E1", "api", "GET /admin/refunds works for any logged-in user", "Deny by default + role check"),
    g.Play("Ben", "I3", "web", "Login says 'unknown user' vs 'wrong password'", ""),
]
for p in round_:
    g.judge(p)
    verdict = f"+{p.points}" if p.points else f"0 ({p.reason})"
    print(f"{p.player:5} plays {p.card} on {p.target:9} -> {verdict}")
print("\nScores:", g.score(round_))
print("\nThreat backlog from this round:")
for item in g.backlog(round_):
    print("  " + item)
