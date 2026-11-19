"""Dependency confusion simulator: two indexes, three resolvers, hash pinning.

The attack (no real network, no real packages)
----------------------------------------------
A company has an INTERNAL package ``acme-ml-utils`` 1.2.0 on its private index. The name is
not registered on the public index. An attacker registers the same name publicly with a much
higher version, 99.0.0. If the installer looks at BOTH indexes and picks the highest version
(what ``pip --extra-index-url`` does), the public package wins.

Resolvers in this file
    naive    highest version across all indexes        (like --extra-index-url)
    scoped   names that match an internal scope are looked up ONLY on the private index
             (like npm scoped registries, or one index with a proxy that blocks internal names)
    locked   exact pins + sha256 hashes + only the allowed index   (pip --require-hashes style)

Artifacts are fake bytes. The "malicious" one only carries a harmless marker string.
"""

from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass, field


def parse_version(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split("."))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Index:
    name: str  # "private" or "public"
    packages: dict[str, dict[str, bytes]] = field(default_factory=dict)  # name -> version -> bytes

    def versions(self, pkg: str) -> list[str]:
        return sorted(self.packages.get(pkg, {}), key=parse_version)

    def artifact(self, pkg: str, version: str) -> bytes:
        return self.packages[pkg][version]


def make_artifact(pkg: str, version: str, origin: str, marker: str = "") -> bytes:
    return f"fake-wheel|{pkg}|{version}|{origin}|{marker}".encode()


def sample_indexes() -> tuple[Index, Index]:
    """Private has the real internal package. Public has numpy and the attacker's copy."""
    private = Index("private", {
        "acme-ml-utils": {"1.2.0": make_artifact("acme-ml-utils", "1.2.0", "private")},
    })
    public = Index("public", {
        "numpy": {"1.26.4": make_artifact("numpy", "1.26.4", "public"),
                  "2.1.0": make_artifact("numpy", "2.1.0", "public")},
        "acme-ml-utils": {"99.0.0": make_artifact("acme-ml-utils", "99.0.0", "public",
                                                  marker="HARMLESS-INSTALL-HOOK-MARKER")},
    })
    return private, public


# ------------------------------------------------------------------------------------
# Requirements with hashes:  name==1.2.0 --hash=sha256:abcd...
# ------------------------------------------------------------------------------------


@dataclass
class Requirement:
    name: str
    pin: str | None = None
    hashes: list[str] = field(default_factory=list)


def parse_requirements(text: str) -> list[Requirement]:
    reqs: list[Requirement] = []
    for raw in text.replace("\\\n", " ").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        spec = parts[0]
        name, _, pin = spec.partition("==")
        hashes = [p.split(":", 1)[1] for p in parts[1:] if p.startswith("--hash=sha256:")]
        reqs.append(Requirement(name.strip(), pin or None, hashes))
    return reqs


@dataclass
class Resolution:
    name: str
    version: str | None
    index: str | None
    ok: bool
    note: str


def naive_resolve(req: Requirement, indexes: list[Index]) -> Resolution:
    """Highest version wins, whichever index it is on. This is the vulnerable behaviour."""
    best: tuple[tuple[int, ...], str, str] | None = None
    for idx in indexes:
        for v in idx.versions(req.name):
            key = (parse_version(v), idx.name, v)
            if best is None or key[0] > best[0]:
                best = key
    if best is None:
        return Resolution(req.name, None, None, False, "not found on any index")
    return Resolution(req.name, best[2], best[1], True, "highest version across all indexes")


def scoped_resolve(req: Requirement, indexes: list[Index], internal_scopes: dict[str, str]) -> Resolution:
    """Internal names (matched by glob) are looked up ONLY on their owner index."""
    for pattern, owner in internal_scopes.items():
        if fnmatch.fnmatch(req.name, pattern):
            idx = next(i for i in indexes if i.name == owner)
            vs = idx.versions(req.name)
            if not vs:
                return Resolution(req.name, None, owner, False,
                                  f"internal name not on {owner}; refusing to look elsewhere")
            return Resolution(req.name, vs[-1], owner, True, f"scoped to {owner}")
    return naive_resolve(req, indexes)  # non-internal names: normal behaviour


def locked_resolve(req: Requirement, indexes: list[Index], allowed_index: str | None = None) -> Resolution:
    """Exact pin and hash required (like pip --require-hashes). Index choice cannot change the result."""
    if not req.pin or not req.hashes:
        return Resolution(req.name, None, None, False, "refused: requirement has no == pin or no hash")
    for idx in indexes:
        if allowed_index and idx.name != allowed_index:
            continue
        if req.pin in idx.packages.get(req.name, {}):
            data = idx.artifact(req.name, req.pin)
            if sha256(data) in req.hashes:
                return Resolution(req.name, req.pin, idx.name, True, "pin and hash match")
            return Resolution(req.name, req.pin, idx.name, False,
                              "HASH MISMATCH: artifact differs from the locked one")
    return Resolution(req.name, req.pin, None, False, "pinned version not found on an allowed index")


def install(requirements_text: str, indexes: list[Index], mode: str,
            internal_scopes: dict[str, str] | None = None, allowed_index: str | None = None) -> list[Resolution]:
    out = []
    for req in parse_requirements(requirements_text):
        if mode == "naive":
            out.append(naive_resolve(req, indexes))
        elif mode == "scoped":
            out.append(scoped_resolve(req, indexes, internal_scopes or {}))
        elif mode == "locked":
            out.append(locked_resolve(req, indexes, allowed_index))
        else:
            raise ValueError(mode)
    return out


def lock_line(name: str, version: str, data: bytes) -> str:
    """What `pip-compile --generate-hashes` writes for you, in miniature."""
    return f"{name}=={version} --hash=sha256:{sha256(data)}"
