# Lesson 04: Transport security

> **Chapter 4** · **Time:** ~4 hours · **You will:** secure stdio servers (process trust, environment inheritance, host-config command lines), use TLS correctly for HTTP transports with Python's `ssl`, validate and pin certificates by SPKI hash, defend a localhost server against DNS rebinding with Host and Origin checks, and lock down endpoints and network exposure.

| | |
|---|---|
| **Syllabus lines** | Transport Security (5 lines) |
| **Already in this repo** | Shadow servers and config discovery: [Module 04, secure-operations](../../04-mcp-security/secure-operations/README.md); TLS and gateways in general: [Module 09, AI gateway](../../09-enterprise-architecture/06-secure-llm-ai-gateway.md) |
| **Lab** | [`transport-security`](labs/transport-security/README.md) (16 tests, local TLS server with a throwaway certificate) |

**Transport state (verify at modelcontextprotocol.io):** the standard transports are **stdio** and **Streamable HTTP**. The older **HTTP+SSE** transport from the 2024-11-05 revision was deprecated in 2025-03-26. The syllabus still says "SSE", so the rules for SSE below apply to Streamable HTTP too (it can use SSE streams inside HTTP responses).

---

## 1. Securing stdio transport

A stdio server is a **child process** started by the host. Nothing travels over a network, but the risks are real.

**Process trust.** The server runs as the **same OS user** as the host. It can read every file that user can read, including `~/.ssh`, browser profiles and other projects. It is third-party code unless you wrote it. Treat "I added a server" like "I installed a program".

**Environment inheritance.** By default a child process inherits the parent's environment. If your shell exports `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN` or `OPENAI_API_KEY`, every stdio server can read them. Pass a minimal environment:

```python
env = stdio_env(os.environ, {"NOTES_DIR": "/data/notes"})   # PATH, HOME, LANG ... only
subprocess.Popen([cmd, *args], env=env, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=False)
```

**The command line in the host config is code.** `mcp.json` (names vary by host) holds `command`, `args` and `env`. Risks the lab's `audit_launch_config()` flags:

| Risk | Example | Fix |
|---|---|---|
| Shell wrapper | `"command": "bash", "args": ["-c", "..."]` | Run the binary directly, `shell=False` |
| Pipe to shell | `curl https://x/i.sh \| sh` | Never; install a reviewed, pinned package |
| Unpinned package | `npx -y @acme/files-mcp` (latest) | `@acme/files-mcp@1.4.2`, or a lockfile / digest |
| Relative command | `./run.sh` | Absolute path to a known binary |
| Inline secret | `"env": {"GITHUB_TOKEN": "ghp_..."}` | Reference a secret store; do not commit |
| Binds everywhere | `--host 0.0.0.0` | Loopback only |

Also protect the **file** (permissions, review in code review, alert on change) because editing it is how an attacker gets code execution. Treat project-level config files from a cloned repository as untrusted: a repository can ship an MCP config that starts a server on open, so hosts ask for approval; do not click through.

**Other stdio hygiene.** Write only protocol messages to stdout (logs go to stderr or a file, never secrets); limit the child with a sandbox (container, seccomp, AppArmor, Windows job object) where you can; set resource limits (CPU, memory, time); kill the process tree on shutdown.

## 2. Implementing TLS for SSE and HTTP transports

Use **HTTPS for every non-loopback HTTP endpoint**. In Python, the `ssl` module does the right thing if you do not turn it off.

```python
import ssl
ctx = ssl.create_default_context()          # system CAs, CERT_REQUIRED, check_hostname=True
ctx.minimum_version = ssl.TLSVersion.TLSv1_2   # TLS 1.3 is used when both sides support it
# Private CA for an internal server:  ssl.create_default_context(cafile="internal-ca.pem")
```

Server side: `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)`, `load_cert_chain(cert, key)`, `minimum_version = TLSv1_2`. In production terminate TLS in a maintained reverse proxy or the web framework's server, use certificates from a CA (public or internal) with automatic renewal, and enable HSTS where a browser is involved.

**Things that break security (do not do them):** `ctx.check_hostname = False`, `ctx.verify_mode = ssl.CERT_NONE`, `requests.get(..., verify=False)`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, trusting "any" certificate in dev and shipping it. A client that skips verification is open to a man-in-the-middle, and tool results can then be altered in transit (finding MT-T06 in chapter 3).

Mutual TLS (client certificates) is useful between a gateway and servers in the same organisation: it authenticates the *client machine*, not the user.

## 3. Certificate validation and pinning

**Validation** (the default context does all of this): chain to a trusted CA, validity dates, hostname matches the certificate's subject alternative names, key usage, optional revocation checking (OCSP stapling; support varies).

**Pinning** adds: "even if a trusted CA signs a certificate for this host, accept only my key". Pin the **SPKI hash** (the SubjectPublicKeyInfo of the certificate), not the whole certificate, so renewing a certificate with the **same key** keeps working.

```python
pin = base64.b64encode(hashlib.sha256(spki_der(cert_der)).digest()).decode()   # same format as curl --pinnedpubkey sha256//...
```

The lab extracts the SPKI with a tiny DER parser and checks it against the `cryptography` library's output in a test. `connect_pinned()` does normal validation first, then compares the pin.

Practical rules:

* Pin **at least two** keys (current and a backup) and plan rotation, or a key change locks every client out.
* Pinning protects against a *mis-issued certificate*; it does not replace hostname validation.
* Browsers dropped HTTP Public Key Pinning (HPKP) because of lockout and abuse risk. Pinning in your **own client to your own server** is different and fine, but it is an operational burden: pin only for high-value links (gateway to a partner).
* For internal servers, a **private CA** plus validation is often simpler than pins.

## 4. Secure configuration of MCP endpoints

**Streamable HTTP servers on localhost.** The specification asks servers to **validate the `Origin` header** to prevent DNS rebinding, to **bind to localhost (127.0.0.1)**, not all interfaces, and to implement authentication (verify the current text).

*DNS rebinding in one paragraph:* an attacker's web page at `evil.example` first resolves to the attacker's server, then re-resolves the same name to `127.0.0.1`. The browser, which thinks the origin is still `evil.example`, now lets the page talk to your local MCP server. Defences:

| Check | What it blocks |
|---|---|
| **Host header allowlist** (`127.0.0.1:PORT`, `localhost:PORT`) | A rebound request still carries `Host: evil.example` |
| **Origin header allowlist** (when present) | Cross-site browser requests; reject `Origin: null` too |
| **Authentication on every request** | Non-browser local programs and anything that slipped through |
| **Bind to 127.0.0.1**, not 0.0.0.0 | Other machines on the network |
| **CORS off by default** | Browsers reading responses |

The lab functions `check_request_origin()` and `safe_bind_address()` have table-driven tests, including the rebinding and `null` origin cases. A missing `Origin` is normal for CLIs and SDKs, so it cannot be the only control.

**Endpoint configuration checklist:** HTTPS only (except loopback), HSTS if browsers are involved, no tokens in URLs, request size and time limits, no verbose errors, health endpoints without data, separate ports for admin and MCP, graceful handling of `Mcp-Session-Id` (do not treat it as authentication; draft spec work may change sessions, so verify), CORS closed.

## 5. Network-level controls for MCP server exposure

* **Do not expose MCP servers to the internet** unless that is the product. Put internal servers behind a VPN, a private link, or an identity-aware proxy.
* **Default-deny egress** from server hosts. A server that only needs one API gets only that destination (blocks exfiltration and SSRF pivots, including the cloud metadata address 169.254.169.254).
* **Firewall rules and security groups** with the smallest source ranges; separate subnets for servers that hold sensitive data.
* **Service mesh or mTLS** between the gateway and servers; the gateway is the only caller.
* **Rate limits and WAF** at the edge for remote servers; see the [`mcp-ai-firewall`](labs/mcp-ai-firewall/README.md) lab for per-client limits.
* **Inventory** what exists. Shadow MCP servers (MCP09) are servers nobody registered. Scan configs and listening ports ([Module 04, secure-operations](../../04-mcp-security/secure-operations/README.md) has discovery code).
* **Containers:** a non-root user, a read-only root filesystem, dropped capabilities, no host mounts you do not need, network policies (Kubernetes: [Module 06](../../06-ai-devsecops/kubernetes/README.md)).

## 6. Quick check

1. Why is a stdio server "local" but not "trusted"?
2. What exactly do you hash for an SPKI pin, and why is that better than hashing the certificate?
3. Explain DNS rebinding in two sentences and name two headers you check.
4. A teammate sets `verify=False` "just for staging". What do you say?

## 7. References

* MCP specification: transports and security best practices (verify revision).
* Python docs: `ssl` module, "Security considerations". RFC 8446 (TLS 1.3), RFC 7469 (HPKP, historical).
* OWASP Transport Layer Security Cheat Sheet; OWASP Docker and Kubernetes security cheat sheets.
* CVE-2025-49596 (MCP Inspector, reported by Oligo): lack of authentication on a local proxy; see [chapter 3](../ch3-threat-modeling-mcp-architectures/01-introduction-and-fundamentals.md).
