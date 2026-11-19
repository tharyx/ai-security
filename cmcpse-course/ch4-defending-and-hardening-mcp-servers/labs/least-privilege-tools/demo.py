"""Demo: role-based tools and resources enforced at list time AND call time."""

from aisec_lab import load_lab_module

rs = load_lab_module(__file__, "rbac_server")


def rpc(server, sess, method, **params):
    return server.handle(sess, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})


viewer, admin = rs.Session("vera", "viewer"), rs.Session("ada", "admin")
server = rs.NotesServer()
print("viewer tools:", [t["name"] for t in rpc(server, viewer, "tools/list")["result"]["tools"]])
print("admin tools :", [t["name"] for t in rpc(server, admin, "tools/list")["result"]["tools"]])
print("viewer calls hidden notes_delete ->", rpc(server, viewer, "tools/call", name="notes_delete", arguments={"id": "notes://public/welcome"})["error"])
print("viewer reads ../admin/payroll    ->", rpc(server, viewer, "resources/read", uri="notes://public/../admin/payroll")["error"])
bad = rs.NotesServer(enforce_calls=False)
print("BUG: filter-only server lets the viewer delete ->", "result" in rpc(bad, viewer, "tools/call", name="notes_delete", arguments={"id": "notes://public/welcome"}))
print("audit:", server.audit)
