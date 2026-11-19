from subagents import Denied, Orchestrator, SharedPool, Vault

vault = Vault({"hr": "FAKE-HR-payroll-table", "code": "FAKE-CODE-repo-token"})
orch = Orchestrator(vault)
a = orch.spawn("hr-agent", ["read_resource", "note"], {"hr"})
b = orch.spawn("code-agent", ["read_resource", "note"], {"code"})
a.remember(a.call("read_resource", "hr"))
print("hr-agent context:", a.context)
print("code-agent context:", b.context)
try:
    b.call("read_resource", "hr")
except Denied as e:
    print("code-agent reading hr ->", e)
print("parent sees:", orch.collect(a)["summary"][:40], "(bounded, untrusted)")
a.terminate()
print("after terminate, context:", a.context)

print("\nVULNERABLE shared pool")
pool = SharedPool(vault, {"hr", "code"})
pool.run("hr-agent", "hr")
print("code-agent can read hr:", pool.run("code-agent", "hr"))
