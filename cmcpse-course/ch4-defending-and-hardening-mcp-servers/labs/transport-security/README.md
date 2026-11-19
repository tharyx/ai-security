# Lab: transport security for MCP (stdio, TLS, pinning, localhost)

**Lesson:** [04 Transport security](../../04-transport-security.md) · This lab covers syllabus items that have no named course exercise (TLS, certificate validation and pinning, secure endpoint configuration, stdio hardening).

Offline. TLS tests create a throwaway self-signed certificate with the `cryptography` package (they skip if it is missing) and run a TLS server on `127.0.0.1` with a free port. Tests: `test_transport_security.py` (16).

| File | Role |
|---|---|
| [`transport_security.py`](transport_security.py) | `client_context()`, `server_context()`, `spki_der()` / `spki_sha256()` (tiny DER parser), `connect_pinned()`, `check_request_origin()`, `safe_bind_address()`, `stdio_env()`, `audit_launch_config()` |
| [`demo.py`](demo.py) | Origin checks, binding, config audit, stdio env (no network) |

```bash
python cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/transport-security/demo.py
python -m pytest cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/transport-security
```

Real demo output:

```text
-- Host / Origin checks (DNS rebinding and cross-site calls)
  {'Host': '127.0.0.1:8080'} -> (True, 'ok')
  {'Host': 'evil.example:8080'} -> (False, "host 'evil.example:8080' not allowed")
  {'Host': '127.0.0.1:8080', 'Origin': 'https://evil.example'} -> (False, "origin 'https://evil.example' not allowed")
-- bind address
  127.0.0.1 -> 127.0.0.1
  0.0.0.0 -> refused: refusing to bind 0.0.0.0: listens on every interface. Use 127.0.0.1, or set allow_external with TLS and auth
-- launch config audit
  files  unpinned_package  npx without an exact version runs whatever is latest (rug pull and typosquat risk)
  files  inline_secret     env API_TOKEN holds a literal secret in the config file; reference a secret store instead
  git    shell_wrapper     launches through a shell: arguments are parsed by the shell (injection risk)
  git    pipe_to_shell     downloads and runs code in one line
-- stdio environment
  {'PATH': '/usr/bin', 'HOME': '/home/a', 'NOTES_DIR': '/data'}
```

What the TLS tests prove: the SPKI hash equals the one computed by the `cryptography` library; a valid certificate with the **wrong pin** is rejected; a self-signed certificate is rejected unless its CA is given; a **hostname mismatch** is rejected; a new key needs a new pin.

## Your tasks

1. Extend `audit_launch_config()` to flag `docker run --privileged` and `-v /:/host` mounts.
2. Add `Mcp-Session-Id` handling to a small HTTP server and show why a session id is not authentication.
3. Make `connect_pinned()` accept two pins (current and backup) and add a rotation test.
4. Run your own host config through the audit (read-only) and list the findings you would fix first.
