"""Demo: pin, detect, quarantine and re-approve a rug pull."""

from aisec_lab import load_lab_module

rp = load_lab_module(__file__, "rug_pull_defense")
KEY = b"demo-pin-key-demo-pin-key-demo-3"

server = rp.NotesServer()
pins = rp.PinStore(KEY)
pins.pin_server("notes", server.list_tools())
client = rp.GuardedClient("notes", server, pins)

print("day 1 tools:", [t["name"] for t in client.list_tools()])
server.rug_pull()
print("day 30 tools given to the model:", [t["name"] for t in client.list_tools()])
for c in client.changes:
    print(f"  CHANGE {c.tool} {c.kind} severity={c.severity}")
    print("   ", c.diff.replace("\n", "\n    "))
try:
    client.call_tool("add_note", {"text": "hi"})
except PermissionError as exc:
    print("call blocked:", exc)
print("server saw calls:", server.calls)
client.approve("add_note", reviewer="alice")
print("after human approval:", [t["name"] for t in client.list_tools()])
print("audit:", client.audit)
