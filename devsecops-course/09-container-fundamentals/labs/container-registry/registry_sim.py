"""In-process container registry simulator: push, pull, tag, digest, delete (no network, no Docker).

Concepts shown:
- A BLOB is a layer or config, addressed by its sha256 digest.
- A MANIFEST lists the config blob and layer blobs; its own digest identifies the image content.
- A TAG is a movable pointer from a name to a manifest digest. A DIGEST never moves.
Real registries speak the OCI Distribution API over HTTPS; the names here (push, pull, tag) are the ideas.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class Ref:
    registry: str
    repo: str
    tag: str | None
    digest: str | None

    def __str__(self) -> str:
        return f"{self.registry}/{self.repo}" + (f":{self.tag}" if self.tag else "") + (f"@{self.digest}" if self.digest else "")


def parse_ref(ref: str) -> Ref:
    """Docker's normalisation: no registry -> docker.io; no namespace on docker.io -> library/; no tag -> latest."""
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    first, _, rest = ref.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = "docker.io", ref
    if registry == "docker.io" and "/" not in path.split(":")[0]:
        path = "library/" + path
    repo, _, tag = path.partition(":")
    if not tag and not digest:
        tag = "latest"
    return Ref(registry, repo, tag or None, digest)


@dataclass
class Registry:
    host: str = "registry.example"
    blobs: dict[str, bytes] = field(default_factory=dict)
    manifests: dict[str, dict] = field(default_factory=dict)      # digest -> manifest
    tags: dict[str, dict[str, str]] = field(default_factory=dict)  # repo -> tag -> digest
    log: list[str] = field(default_factory=list)

    def push_blob(self, data: bytes) -> str:
        d = sha256(data)
        self.blobs[d] = data
        return d

    def push_image(self, repo: str, tag: str, config: dict, layers: list[bytes]) -> str:
        cfg_digest = self.push_blob(json.dumps(config, sort_keys=True).encode())
        manifest = {"schemaVersion": 2, "config": cfg_digest, "layers": [self.push_blob(l) for l in layers]}
        digest = sha256(json.dumps(manifest, sort_keys=True).encode())
        self.manifests[digest] = manifest
        self.tags.setdefault(repo, {})[tag] = digest
        self.log.append(f"push {repo}:{tag} -> {digest[:19]}")
        return digest

    def tag(self, repo: str, existing: str, new_tag: str) -> None:
        """`docker tag` + push: point another tag at the same content (no data copied)."""
        self.tags[repo][new_tag] = self.tags[repo][existing]
        self.log.append(f"tag {repo}:{new_tag} -> same digest as {existing}")

    def resolve(self, ref: str) -> str:
        r = parse_ref(ref)
        if r.digest:
            if r.digest not in self.manifests:
                raise KeyError(f"manifest unknown: {r.digest[:19]}")
            if r.tag and self.tags.get(r.repo, {}).get(r.tag) not in (None, r.digest):
                pass  # with tag AND digest, Docker ignores the tag
            return r.digest
        try:
            return self.tags[r.repo][r.tag]
        except KeyError:
            raise KeyError(f"manifest unknown: {r.repo}:{r.tag}") from None

    def pull(self, ref: str) -> dict:
        digest = self.resolve(ref)
        m = self.manifests[digest]
        for b in [m["config"], *m["layers"]]:
            if b not in self.blobs:
                raise KeyError(f"blob missing: {b[:19]}")
        self.log.append(f"pull {ref} -> {digest[:19]}")
        return {"digest": digest, "manifest": m, "verified": all(sha256(self.blobs[b]) == b for b in [m["config"], *m["layers"]])}

    def delete(self, repo: str, digest: str) -> None:
        """Delete by DIGEST (the registry API does not delete by tag). Tags pointing at it dangle and are removed."""
        self.manifests.pop(digest, None)
        self.tags[repo] = {t: d for t, d in self.tags.get(repo, {}).items() if d != digest}

    def catalog(self) -> list[str]:
        return sorted(self.tags)

    def list_tags(self, repo: str) -> list[str]:
        return sorted(self.tags.get(repo, {}))

    def untagged(self, repo: str) -> list[str]:
        """Manifests no tag points at: reachable only by digest (and garbage-collectable)."""
        tagged = set(self.tags.get(repo, {}).values())
        return [d for d in self.manifests if d not in tagged]
