# Lab: least-privilege tool permissions on a running MCP server

**Course exercise:** Configure least-privilege tool permissions on a running MCP server · **Lesson:** [02 section 4 to 5](../../02-authentication-and-authorization.md), [03 section 2](../../03-secure-tool-and-resource-design.md)

An in-process JSON-RPC server (`NotesServer`) with a **role to tools and resources** policy in [`policy.yaml`](policy.yaml). The same two functions decide at `tools/list` (filter) **and** `tools/call` (enforce), and at `resources/list` and `resources/read`. Tests: `test_rbac_server.py` (12).

| File | Role |
|---|---|
| [`policy.yaml`](policy.yaml) | Roles `viewer`, `analyst`, `admin`: allowed tools, resource patterns, per-tool limits. Unknown role gets nothing |
| [`rbac_server.py`](rbac_server.py) | The running server: `handle(session, request)`; `enforce_calls=False` reproduces the filter-only bug |
| [`demo.py`](demo.py) | Viewer and admin sessions |

```bash
python cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/least-privilege-tools/demo.py
python -m pytest cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/least-privilege-tools
```

Real demo output:

```text
viewer tools: ['notes_search', 'notes_read']
admin tools : ['notes_search', 'notes_read', 'notes_write', 'notes_delete', 'notes_export']
viewer calls hidden notes_delete -> {'code': -32001, 'message': "tool 'notes_delete' is not permitted for this session"}
viewer reads ../admin/payroll    -> {'code': -32001, 'message': 'resource is not permitted for this session'}
BUG: filter-only server lets the viewer delete -> True
audit: [{'user': 'vera', 'role': 'viewer', 'method': 'tools/call', 'target': 'notes_delete', 'decision': 'deny'}, {'user': 'vera', 'role': 'viewer', 'method': 'resources/read', 'target': 'notes://public/../admin/payroll', 'decision': 'deny'}]
```

## Your tasks

1. Edit `policy.yaml`: give `analyst` the resource `notes://admin/reports/*` and nothing else new. Prove with two tests that `notes://admin/payroll` is still denied.
2. Add a role `auditor` that can read all resources but call no write tool. Check `tools/list` and `tools/call`.
3. Make `notes_export` require a second condition: only while `session.mfa` is true. Where does that check belong?
4. Replace the deny error with a response that is identical for "hidden" and "unknown" tools. Is that better or worse for debugging and for audit? Decide and write it down.
