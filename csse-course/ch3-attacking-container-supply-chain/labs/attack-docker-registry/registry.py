"""A tiny in-process simulation of the Docker Registry HTTP API v2 (no sockets, no network).

Two modes:
  Registry()                                  open: no auth, plaintext, mutable tags  (the classic exposed registry)
  Registry(auth=True, require_tls=True, immutable_tags=True, ...)   hardened

Only the endpoints an attacker or auditor needs: /v2/, /v2/_catalog, tags/list, manifests (GET, PUT, DELETE).
Real registries (Distribution, Harbor, ECR, GHCR) have the same URL shapes.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass, field

NAME = r"(?P<name>[a-z0-9]+(?:[._/-][a-z0-9]+)*)"
ROUTES = [
    ("base", re.compile(r"^/v2/?$")),
    ("catalog", re.compile(r"^/v2/_catalog$")),
    ("tags", re.compile(rf"^/v2/{NAME}/tags/list$")),
    ("manifest", re.compile(rf"^/v2/{NAME}/manifests/(?P<ref>[A-Za-z0-9_.:-]+)$")),
]


@dataclass
class Response:
    status: int
    body: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)


def digest_of(manifest: dict) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Registry:
    def __init__(self, *, auth: bool = False, require_tls: bool = False, immutable_tags: bool = False,
                 tokens: dict[str, list[str]] | None = None) -> None:
        self.auth, self.require_tls, self.immutable = auth, require_tls, immutable_tags
        self.tokens = tokens or {}   # token -> scopes such as "repository:shop/*:pull" or "registry:catalog:*"
        self.manifests: dict[str, dict[str, dict]] = {}   # repo -> digest -> manifest
        self.tags: dict[str, dict[str, str]] = {}         # repo -> tag -> digest
        self.audit: list[str] = []

    # ---- helpers
    def _allowed(self, headers: dict, resource: str, action: str) -> bool:
        if not self.auth:
            return True
        token = headers.get("Authorization", "").removeprefix("Bearer ").strip()
        for scope in self.tokens.get(token, []):
            kind, _, rest = scope.partition(":")
            pattern, _, actions = rest.rpartition(":")
            if kind == resource.split(":")[0] and fnmatch.fnmatch(resource.split(":", 1)[1], pattern) and action in actions.split(","):
                return True
        return False

    def put_image(self, repo: str, tag: str, manifest: dict) -> str:
        """Seeding helper (not an HTTP call)."""
        d = digest_of(manifest)
        self.manifests.setdefault(repo, {})[d] = manifest
        self.tags.setdefault(repo, {})[tag] = d
        return d

    # ---- the API
    def handle(self, method: str, path: str, *, headers: dict | None = None, body: dict | None = None,
               scheme: str = "http") -> Response:
        headers = headers or {}
        if self.require_tls and scheme != "https":
            return Response(403, {"errors": [{"code": "DENIED", "message": "TLS required"}]})
        for kind, rx in ROUTES:
            m = rx.match(path)
            if m:
                break
        else:
            return Response(404, {"errors": [{"code": "NAME_UNKNOWN"}]})
        name = m.groupdict().get("name", "")
        resource = {"base": "registry:base", "catalog": "registry:catalog"}.get(kind, f"repository:{name}")
        action = {"GET": "pull", "HEAD": "pull", "PUT": "push", "DELETE": "delete"}.get(method, "other")
        if kind == "catalog":
            action = "*"
        if self.auth and not self._allowed(headers, resource, action) and kind != "base":
            return Response(401, {"errors": [{"code": "UNAUTHORIZED"}]},
                            {"WWW-Authenticate": 'Bearer realm="https://auth.registry.example/token"'})
        if kind == "base":
            if self.auth and not headers.get("Authorization"):
                return Response(401, {}, {"WWW-Authenticate": 'Bearer realm="https://auth.registry.example/token"'})
            return Response(200, {})
        if kind == "catalog":
            return Response(200, {"repositories": sorted(self.tags)})
        if kind == "tags":
            if name not in self.tags:
                return Response(404, {"errors": [{"code": "NAME_UNKNOWN"}]})
            return Response(200, {"name": name, "tags": sorted(self.tags[name])})
        ref = m.group("ref")
        if method == "GET":
            digest = self.tags.get(name, {}).get(ref, ref)
            manifest = self.manifests.get(name, {}).get(digest)
            return Response(200, manifest, {"Docker-Content-Digest": digest}) if manifest else Response(404, {"errors": [{"code": "MANIFEST_UNKNOWN"}]})
        if method == "PUT":
            d = digest_of(body)
            old = self.tags.get(name, {}).get(ref)
            if self.immutable and old and old != d:
                return Response(409, {"errors": [{"code": "TAG_INVALID", "message": "tag is immutable"}]})
            self.manifests.setdefault(name, {})[d] = body
            self.tags.setdefault(name, {})[ref] = d
            self.audit.append(f"PUT {name}:{ref} -> {d[:19]}")
            return Response(201, {}, {"Docker-Content-Digest": d})
        if method == "DELETE":
            if not ref.startswith("sha256:") or ref not in self.manifests.get(name, {}):
                return Response(404, {"errors": [{"code": "MANIFEST_UNKNOWN"}]})
            del self.manifests[name][ref]
            self.tags[name] = {t: d for t, d in self.tags[name].items() if d != ref}
            self.audit.append(f"DELETE {name}@{ref[:19]}")
            return Response(202)
        return Response(405)


def sample_manifest(version: str, *, secret_env: str | None = None, extra_layer: str | None = None) -> dict:
    layers = [{"digest": "sha256:" + hashlib.sha256(f"base-{version}".encode()).hexdigest(), "size": 1000}]
    if extra_layer:
        layers.append({"digest": "sha256:" + hashlib.sha256(extra_layer.encode()).hexdigest(), "size": 64})
    cfg = {"Env": [secret_env] if secret_env else [], "Entrypoint": ["/app/server"]}
    return {"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": cfg, "layers": layers}
