# Lab: Attacking docker registry

**Course exercise:** "Attacking docker registry". Lessons: [03 section 3](../../03-attacking-the-container-supply-chain.md#3-insecure-container-registry).

**Time:** 60 minutes. **Safety:** the registry is a Python object. `handle(method, path, ...)` mimics the Registry HTTP API v2; no sockets, no network. Never run this kind of enumeration against a registry you do not own.

## What it models

| Mode | Behaviour |
|---|---|
| `Registry()` (open) | no auth, plaintext allowed, mutable tags, anyone can push and delete |
| `Registry(auth=True, require_tls=True, immutable_tags=True, tokens=...)` | bearer tokens with scopes (`repository:shop/*:pull,push`, `registry:catalog:*`), TLS required, existing tags cannot be overwritten (409), audit log |

[attacker.py](attacker.py) enumerates the catalog, tags and manifests, collects secrets baked into configs, and tries to overwrite a tag with a manifest that has an extra canary layer.

## Steps

```text
.venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/attack-docker-registry/demo.py
.venv/Scripts/python -m pytest csse-course/ch3-attacking-container-supply-chain/labs/attack-docker-registry -v
```

1. Read the open-registry half: catalog, secret, overwrite all succeed.
2. Read the hardened half: 401 without a token, 403 over HTTP, 401 for a reader that pushes, 409 for overwrite, 201 for a new tag.
3. Give the CI token `registry:catalog:*` too, then ask: is that necessary? (No. Least privilege: CI needs push to its repos only.)
4. Remove `immutable_tags=True` and re-run the CI overwrite. What stops it now? (Only scope; so a stolen CI token can poison tags. Immutability is a second layer.)

## Expected output (real run)

```text
== OPEN registry (no auth, http, mutable tags) ==
catalog status : 200 | repos: {'shop/api': ['1.0'], 'shop/web': ['2.3']}
secrets found  : [('shop/api:1.0', 'DB_PASSWORD')]
poison tag     : 201 (201 = accepted)
digest changed : sha256:8b683cb11e3f -> sha256:f064e7a40d2a
== HARDENED registry (token auth, TLS only, immutable tags) ==
anonymous catalog     : 401
plain http with token : 403
reader pushes         : 401
ci overwrites 1.0     : 409 (409 = immutable tag)
ci pushes new tag 1.1 : 201
```

## Real-tool twin

Run a local `registry:2` and a Harbor instance in your course lab ([real-tools/docker.md](../../real-tools/docker.md)). Check Harbor's tag immutability rules and robot accounts. Real registries return their own status codes; compare with your registry's documentation.
