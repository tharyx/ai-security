"""Demo: an MCP server that fetches secrets from a (mock) vault at call time."""

import json

from aisec_lab import load_lab_module

mv = load_lab_module(__file__, "mock_vault")
vs = load_lab_module(__file__, "vault_mcp_server")


class Clock:
    t = 1_000_000.0

    def __call__(self):
        return self.t


clock = Clock()
vault = mv.MockVault(now=clock)
vault.add_policy("mcp-reporting", read_kv=["partner"], db_roles=["reporting"])
vault.add_approle("report-server", "bootstrap-secret-id", ["mcp-reporting"])
vault.put_kv("partner", {"api_key": "pk-live-4f9a7c2e1b"})
addr = vault.start()
redact = vs.Redactor()
server = vs.SecretsServer(vs.VaultClient(addr, "report-server", "bootstrap-secret-id", redact, now=clock),
                          vault.db_login_ok, lambda k: vault.partner_key_ok("partner", k), now=clock)


def call(name, **args):
    r = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})
    return r["result"]["content"][0]["text"]


try:
    print("tools/list has secrets?   ", "pk-live" in json.dumps(server.TOOLS))
    print("run_report                ", call("run_report", month="2026-10"))
    print("sync_partner              ", call("sync_partner"))
    print("DB creds fetched so far   ", server.fetches, "(cached within the lease)")
    clock.t += 100
    call("run_report", month="2026-11")
    print("after 100s (lease 120s)   ", server.fetches, "fetches: renewed early")
    vault.rotate_kv("partner", {"api_key": "pk-live-NEW-9d8c7b6a"})
    print("after rotating the key    ", call("sync_partner"))
    server._log("debug: key=pk-live-NEW-9d8c7b6a password=hunter2hunter2")
    print("log (redacted):")
    for line in server.log:
        print("   ", line)
finally:
    vault.stop()
