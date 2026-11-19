"""Demo: an AI firewall in front of an MCP server."""

from aisec_lab import load_lab_module

fw = load_lab_module(__file__, "firewall")
clock = [0.0]
f = fw.Firewall(fw.fake_upstream, now=lambda: clock[0])   # a fake clock so the rate limit refills between lines


def call(tool, **args):
    clock[0] += 2
    r = f.handle("ide-1", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}})
    return r["error"]["message"] if "error" in r else r["result"]["content"][0]["text"]


print("tools/list         :", [t["name"] for t in f.handle("ide-1", {"jsonrpc": "2.0", "id": 0, "method": "tools/list"})["result"]["tools"]])
for label, tool, args in [("normal read", "notes_read", {"id": "welcome"}),
                          ("unlisted tool", "run_shell", {"cmd": "ls"}),
                          ("path traversal", "notes_read", {"id": "../../etc/passwd"}),
                          ("secret in args", "notes_search", {"q": "key sk-ABCDEFGHIJKL123456"}),
                          ("PII in result", "notes_read", {"id": "contact"}),
                          ("injection in result", "notes_read", {"id": "evil"}),
                          ("tracking image", "fetch_page", {"url": "tracker"})]:
    print(f"{label:<19}:", call(tool, **args))
print("\nevents:")
for e in f.events:
    print(f"  {e.direction:<7} {e.tool:<13} {e.action:<10} {'; '.join(e.reasons)}")
