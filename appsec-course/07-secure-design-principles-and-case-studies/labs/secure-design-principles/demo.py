import secrets
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import principles as p  # noqa: E402

ACL = {"clerk": {"read"}, "admin": {"read", "delete"}}
rows = []


def row(principle, attack, vuln, good):
    rows.append((principle, attack, vuln, good))


row("Economy of mechanism", "send X-Internal-User: admin",
    p.ManyPathAuth({}, {}).authenticate({"X-Internal-User": "admin"}), p.OnePathAuth({}).authenticate({"X-Internal-User": "admin"}))
row("Fail-safe defaults", "user with no role deletes", p.allowed_fail_open({}, "delete", ACL), p.allowed_fail_safe({}, "delete", ACL))
results = []
for cls in (p.CachedAuthz, p.MediatedAuthz):
    store = {"mallory": {"delete"}}
    a = cls(store)
    sid = a.login("mallory")
    store["mallory"].clear()
    results.append(a.can(sid, "delete"))
row("Complete mediation", "delete after access revoked", *results)
key = secrets.token_bytes(32)
row("Open design", "forge token for user 1", p.obscure_verify(p.obscure_token(1)), p.open_verify("1." + "0" * 64, key))
row("Separation of privilege", "requester approves own 50k refund",
    p.refund_single_key(50_000, "eve", ["eve"]), p.refund_two_person(50_000, "eve", ["eve"]))
owner, reader = p.report_db(False), p.report_db(True)
p.run_report(owner, "DELETE FROM orders")
try:
    p.run_report(reader, "DELETE FROM orders")
    blocked = "deleted"
except sqlite3.DatabaseError as e:
    blocked = f"denied ({e})"
row("Least privilege", "ad-hoc report runs DELETE",
    f"deleted, {owner.execute('SELECT COUNT(*) FROM orders').fetchone()[0]} rows left", blocked)
build = lambda t, r: f"{r} for {t}"  # noqa: E731
s, t = p.SharedReportCache(), p.TenantReportCache()
s.get("acme", "revenue", build), t.get("acme", "revenue", build)
row("Least common mechanism", "globex asks for 'revenue'", s.get("globex", "revenue", build), t.get("globex", "revenue", build))
row("Psychological acceptability", "password 'Summer2026!'", p.complexity_policy("Summer2026!"), p.usable_policy("Summer2026!"))
row("Psychological acceptability", "passphrase of 4 words", p.complexity_policy("correct horse battery staple"),
    p.usable_policy("correct horse battery staple"))

print(f"{'Principle':28} {'Attack / input':36} {'Vulnerable':28} Principled")
for r in rows:
    print(f"{r[0]:28} {r[1]:36} {str(r[2]):28} {r[3]}")
