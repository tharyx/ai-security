"""Demo: defending OAuth scopes on an MCP server."""

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "oauth_scopes")
KEY = b"demo-key-demo-key-demo-key-demo!"
issuer = m.Issuer(KEY)
server = m.ScopedServer(KEY)


def show(label, token, tool, **args):
    r = server.handle(token, "tools/call", {"name": tool, "arguments": args})
    print(f"{label:<44} -> {r}")


reader = issuer.mint("alice", "reader-app", ["notes:read"], m.AUDIENCE)
show("reader reads a note", reader, "notes.read", id="n1")
show("reader tries to write", reader, "notes.write", id="n2", text="x")
show("token minted for the calendar server", issuer.mint("a", "admin-app", ["notes:read"], m.OTHER_AUDIENCE), "notes.read", id="n1")
show("wildcard scope token", issuer.mint("m", "reader-app", ["notes:read", "*"], m.AUDIENCE), "notes.read", id="n1")
show("unlisted tool, admin token", issuer.mint("r", "admin-app", ["notes:read", "notes:write", "notes:delete"], m.AUDIENCE), "notes.export")
print("tools/list for the reader:", server.handle(reader, "tools/list"))
