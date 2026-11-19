# Lab: Standing Up OpenClaw and Reproducing a Documented Misconfiguration (offline twin)

**Course exercise:** "Standing Up OpenClaw and Reproducing a Documented Misconfiguration". Lessons: [03 OpenClaw case study](../../03-openclaw-case-study.md), [05 defending](../../05-defending-computer-use-and-coding-agents.md).

**Time:** 45 minutes. **Safety:** this lab uses a **simulated** gateway. It contains no OpenClaw code. The socket **always binds to `127.0.0.1`** on an ephemeral port, even when the simulated config says `0.0.0.0` (that value is only data for the auditor). The token is `FAKE-GATEWAY-TOKEN-0000`. Never scan or probe real instances on the internet.

## What you reproduce

The widely reported OpenClaw problems were a class of mistake: a local agent gateway with defaults that were too open, and a token that a web page could reach. The simulated gateway has five switches:

| Flaw | Config field | Auditor ID |
|---|---|---|
| Listens on all interfaces | `bind: 0.0.0.0` | `GW-BIND` |
| No authentication | `auth_token: null` | `GW-AUTH` |
| Any web origin may call it | `allowed_origins: ["*"]` | `GW-ORIGIN` |
| API returns the token | `expose_token_in_api: true` | `GW-TOKEN-EXPOSED` |
| Old version | `version < fixed release` (fictional number) | `GW-VERSION` |

The **auditor** checks the config (static) and then sends the requests a web page on `http://evil.example` would send (live probes): `PROBE-NOAUTH`, `PROBE-CROSS-ORIGIN`, `PROBE-TOKEN-LEAK`.

## Steps

```text
.venv/Scripts/python caase-course/ch4-computer-use-browser-and-coding-agents/labs/openclaw-misconfiguration/demo.py
.venv/Scripts/python -m pytest caase-course/ch4-computer-use-browser-and-coding-agents/labs/openclaw-misconfiguration -v
```

1. Run the demo. Compare the INSECURE and HARDENED blocks.
2. In `sim_gateway.py`, copy `HARDENED_CONFIG` and break **one** field at a time. Which static ID and which probe fires? (The tests do this for you.)
3. Set `auth_token` but leave `allowed_origins: ["*"]`. What can a web page still do? (Read responses if it learns the token; the origin rule is a second line of defense.)
4. Remove auth but keep a strict origin list. Why is that still bad? (Any local process, and any non-browser client, can call it. The test `test_origin_check_alone_is_not_enough_without_auth` proves it.)

## Expected output (real run)

```text
== INSECURE ==
static findings:
  [high] GW-BIND: gateway is configured to listen on all interfaces
  [critical] GW-AUTH: no auth token configured
  [high] GW-ORIGIN: any web origin is allowed (CORS wildcard)
  [critical] GW-TOKEN-EXPOSED: the session API returns the token to callers
  [high] GW-VERSION: version 2026.1.0 is older than the fixed release
live probes (loopback, ephemeral port):
  [critical] PROBE-NOAUTH: session API answers without credentials
  [high] PROBE-CROSS-ORIGIN: a foreign origin can read the response
  [critical] PROBE-TOKEN-LEAK: a foreign origin obtained a token (simulated token theft)

== HARDENED ==
static findings:
  [-] none: clean
live probes (loopback, ephemeral port):
  [-] none: clean
```

## Standing up the real OpenClaw safely (hedged guide; not run by the tests)

Check the official documentation first (project names, flags and defaults change; the project was renamed twice in early 2026). Only install from the official project site or repository, because typosquat domains and packages appeared during the renames.

1. **Isolate.** Use a throwaway VM, or a container on a machine with nothing valuable. Do not install it on the laptop that holds your SSH keys and browser sessions.
2. **Requirements.** The reports say Node 22 or newer. Verify.
3. **Update first.** Install a release newer than the one that fixed CVE-2026-25253 (disclosed about 30 Jan 2026). Verify the fixed version in the advisory.
4. **Bind to loopback.** Keep the gateway on `127.0.0.1`. If you need remote access, use a VPN or an authenticated reverse proxy with TLS. Do not publish the port.
5. **Require authentication.** Set a long random token. Treat it like a password.
6. **Do not expose it.** No port forwarding, no "any interface" setting, no public tunnel.
7. **Skills.** Install none at first. When you do, vet each one (lab [skill-vetting](../skill-vetting/README.md)).
8. **Real model keys.** Use a scoped key with a spending limit, never your main key.
9. **Re-run the audit** ([harness-security-audit](../harness-security-audit/README.md)) against your config.

Laptop note: the learner laptop has no GPU and little disk space. Use a hosted model API for a real OpenClaw trial; this offline twin needs nothing.
