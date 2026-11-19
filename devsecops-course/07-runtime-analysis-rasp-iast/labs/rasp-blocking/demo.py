import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from aisec_lab import load_lab_module  # noqa: E402

p = load_lab_module(__file__, "protect")
tinyapp, agent_mod = p.tinyapp, p.agent_mod

ATTACKS = [
    ("sqli", "user_by_name", {"name": "x' OR '1'='1"}),
    ("path traversal", "read_doc", {"file": "../../etc/passwd"}),
    ("command inj.", "ping", {"host": "127.0.0.1; cat /etc/passwd"}),
    ("benign user", "user_by_name", {"name": "alice"}),
    ("safe query, hostile text", "user_by_id", {"id": "1' OR '1'='1"}),
]

for label, mode in (("NO PROTECTION (report only)", "report"), ("PROTECT MODE", "block")):
    app = tinyapp.App()
    with agent_mod.IastAgent(mode=mode) as agent:
        print(f"== {label} ==")
        for name, handler, params in ATTACKS:
            status, body = p.handle(app, agent, handler, params)
            print(f"  {name:26} -> {status}  {str(body)[:60]}")
    print("  commands that reached the shell stub:", app.shell.executed)

print("\n== monitor-only for command injection (block_kinds = SQL only) ==")
app = tinyapp.App()
with agent_mod.IastAgent(mode="block", block_kinds={"SQL_INJECTION"}) as agent:
    print("  ", p.handle(app, agent, "ping", {"host": "1.1.1.1; id"}))
    print("   finding blocked flag:", agent.findings[0].blocked)

print("\n== overhead (microseconds per request, toy app, your numbers will differ) ==")
r = p.benchmark(3000)
for k, v in r["us_per_request"].items():
    print(f"  {k:12} {v:8.1f} us   x{r['overhead_x'][k]:.2f}")
