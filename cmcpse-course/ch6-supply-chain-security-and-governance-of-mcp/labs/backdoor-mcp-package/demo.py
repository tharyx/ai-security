"""Demo: a "new version" of a third-party MCP package adds a hidden BCC. Four defences catch it."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import defenses as d  # noqa: E402

HERE = Path(__file__).resolve().parent
OLD, NEW = HERE / "packages" / "mailer_1_0_15", HERE / "packages" / "mailer_1_0_16"
old_mod, new_mod = d.load_package_server(OLD), d.load_package_server(NEW)

print("== no defence: what the attacker's sink receives from 1.0.16 ==")
t = d.RecordingTransport()
new_mod.handle({"id": 1, "method": "tools/call", "params": {"arguments": {"to": "bob@customer.example", "subject": "invoice", "body": "BODY-CANARY"}}}, t)
print("recipients:", t.recipients())

print("\n== 1. diff review (1.0.15 -> 1.0.16) ==")
for severity, reason in d.review_diff((OLD / "server.py").read_text(), (NEW / "server.py").read_text()):
    print(f"  [{severity}] {reason}")

print("\n== 2. behavior contract test ==")
print("  1.0.15:", d.behavior_check(old_mod) or "ok")
print("  1.0.16:", d.behavior_check(new_mod))

print("\n== 3. egress allowlist (customer.example only) ==")
guard = d.EgressGuard(d.RecordingTransport(), {"customer.example"})
try:
    new_mod.handle({"id": 1, "method": "tools/call", "params": {"arguments": {"to": "bob@customer.example", "subject": "s", "body": "b"}}}, guard)
except d.EgressBlocked as exc:
    print("  blocked:", exc, "| delivered messages:", len(guard.inner.sent))

print("\n== 4. pinning ==")
lock = d.make_lock(OLD)
print("  lock:", lock)
print("  verify 1.0.15:", d.verify_pin(OLD, lock) or "ok")
print("  verify 1.0.16:", d.verify_pin(NEW, lock))
cfg = {"mcpServers": {"mail": {"command": "npx", "args": ["-y", "mailer-mcp@latest"]}, "mail2": {"command": "npx", "args": ["mailer-mcp@1.0.15"]}}}
print("  host config check:", d.check_host_config(cfg))
