"""Two-index package resolver simulation for dependency confusion.

Everything is in memory: there is no network and no real package manager.
Two indexes exist: a PRIVATE one (your company) and a PUBLIC one (anyone can publish).
The attacker publishes the same *name* as an internal package on the public index
with a very high version. Different resolver policies react differently.
"""

from __future__ import annotations

from dataclasses import dataclass, field

CANARY = "CANARY-PUBLIC-INSTALL-SCRIPT-RAN"  # stands for "attacker code would run here"


def vkey(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("."))


@dataclass
class Index:
    name: str
    packages: dict[str, dict[str, str]] = field(default_factory=dict)  # pkg -> {version: sha256}

    def versions(self, pkg: str) -> dict[str, str]:
        return self.packages.get(pkg, {})


@dataclass
class Resolution:
    package: str
    version: str | None
    index: str | None
    reason: str


def resolve_highest_version(pkg: str, indexes: list[Index]) -> Resolution:
    """VULNERABLE: like a client that merges all indexes (extra-index-url style).

    It looks at every index and takes the highest version. The attacker wins with 99.0.0.
    """
    best: tuple[str | None, str | None] = (None, None)
    for idx in indexes:
        for ver in idx.versions(pkg):
            if best[0] is None or vkey(ver) > vkey(best[0]):
                best = (ver, idx.name)
    if best[0] is None:
        return Resolution(pkg, None, None, "not found")
    return Resolution(pkg, best[0], best[1], "highest version across all indexes")


def resolve_pinned_index(pkg: str, indexes: list[Index], routing: dict[str, str]) -> Resolution:
    """DEFENSE 1: each package is routed to exactly one index (index pinning / proxy rules)."""
    target = routing.get(pkg, "public")
    for idx in indexes:
        if idx.name == target:
            vers = idx.versions(pkg)
            if not vers:
                return Resolution(pkg, None, None, f"not on routed index {target}")
            top = max(vers, key=vkey)
            return Resolution(pkg, top, idx.name, f"routed to {target}")
    return Resolution(pkg, None, None, f"index {target} unknown")


def resolve_reserved_prefix(pkg: str, indexes: list[Index], internal_prefixes: tuple[str, ...]) -> Resolution:
    """DEFENSE 2: names under an internal prefix may only come from the private index
    (a namespace or scope rule, or a proxy that blocks those names from upstream)."""
    if pkg.startswith(internal_prefixes):
        return resolve_pinned_index(pkg, indexes, {pkg: "private"})
    return resolve_pinned_index(pkg, indexes, {})


def resolve_with_lock(pkg: str, indexes: list[Index], lock: dict[str, str]) -> Resolution:
    """DEFENSE 3: a lock file with hashes. Only a file whose sha256 is in the lock is accepted."""
    want = lock.get(pkg)
    if want is None:
        return Resolution(pkg, None, None, "not in lock file")
    for idx in indexes:
        for ver, digest in idx.versions(pkg).items():
            if digest == want:
                return Resolution(pkg, ver, idx.name, "hash matches lock")
    return Resolution(pkg, None, None, "no candidate matches the locked hash")


def install(res: Resolution, indexes: list[Index], sink: list[str]) -> None:
    """Pretend install: a public 99.x candidate's 'install script' appends the canary."""
    if res.index == "public" and res.version and res.version.startswith("99."):
        sink.append(CANARY)


def ide_quick_fix(import_name: str, indexes: list[Index]) -> str | None:
    """Hedged model of an IDE 'install the missing package' helper that looks a name up on the
    public index only. Real IDE behaviour varies; the lesson is the pattern: a tool that maps an
    import or an extension recommendation to a public name without asking who owns it."""
    for idx in indexes:
        if idx.name == "public" and idx.versions(import_name):
            return f"pip install {import_name}=={max(idx.versions(import_name), key=vkey)}"
    return None


def build_fixture() -> tuple[list[Index], dict[str, str]]:
    private = Index("private", {
        "acme-billing-utils": {"1.2.0": "sha-priv-billing-120"},
    })
    public = Index("public", {
        "acme-billing-utils": {"99.0.0": "sha-attacker-billing-9900"},  # squatted internal name
        "requests": {"2.31.0": "sha-pub-requests-2310"},
    })
    lock = {"acme-billing-utils": "sha-priv-billing-120", "requests": "sha-pub-requests-2310"}
    return [private, public], lock
