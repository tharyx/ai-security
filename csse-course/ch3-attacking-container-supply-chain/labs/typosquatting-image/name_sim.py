"""Detect typosquatted container image names (Docker Hub style) and enforce registry allowlists and digest pins.

An image reference is [registry/][namespace/]name[:tag][@digest]. Docker Hub shortcuts: `nginx` means
`docker.io/library/nginx:latest`. Typosquats live in the namespace/name part: `nqinx`, `ngnix`, `library-nginx`,
`nginx-official`, or a user namespace such as `nginx/nginx`.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

HOMOGLYPHS = {"rn": "m", "vv": "w", "cl": "d", "0": "o", "1": "l", "q": "g", "5": "s"}
SUFFIXES = ("-official", "-latest", "-secure", "-free", "-pro", "-new", "-v2", "official-", "-image", "-docker")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class Ref:
    registry: str
    namespace: str
    name: str
    tag: str
    digest: str

    @property
    def repo(self) -> str:
        return f"{self.registry}/{self.namespace}/{self.name}"


def parse(ref: str) -> Ref:
    digest = ""
    if "@" in ref:
        ref, _, digest = ref.partition("@")
    tag = "latest"
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, _, tag = ref.rpartition(":")
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, parts = parts[0], parts[1:]
    else:
        registry = "docker.io"
    if registry in ("docker.io", "index.docker.io") and len(parts) == 1:
        parts = ["library"] + parts
    return Ref("docker.io" if registry == "index.docker.io" else registry, "/".join(parts[:-1]), parts[-1], tag, digest)


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalise_homoglyphs(s: str) -> str:
    for src, dst in HOMOGLYPHS.items():
        s = s.replace(src, dst)
    return s


def is_transposition(a: str, b: str) -> bool:
    return len(a) == len(b) and a != b and sum(x != y for x, y in zip(a, b)) == 2 and sorted(a) == sorted(b)


@dataclass(frozen=True)
class Suspicion:
    reason: str
    looks_like: str


def check_name(ref: str, popular: list[str]) -> list[Suspicion]:
    """popular is a list of canonical names such as 'library/nginx'. Compare the image name part."""
    r = parse(ref)
    out: list[Suspicion] = []
    for pop in popular:
        pop_ns, _, pop_name = pop.rpartition("/")
        if r.name == pop_name and r.namespace == pop_ns:
            return []  # exact match with the real thing
    for pop in popular:
        pop_ns, _, pop_name = pop.rpartition("/")
        if r.name == pop_name and r.namespace != pop_ns and r.registry == "docker.io":
            out.append(Suspicion(f"same name '{r.name}' under a different namespace '{r.namespace}'", pop))
        elif is_transposition(r.name, pop_name):
            out.append(Suspicion("two letters swapped", pop))
        elif r.name != pop_name and normalise_homoglyphs(r.name) == normalise_homoglyphs(pop_name):
            out.append(Suspicion("look-alike characters (homoglyph)", pop))
        elif 0 < levenshtein(r.name, pop_name) <= (1 if len(pop_name) <= 5 else 2) and r.name != pop_name:
            out.append(Suspicion(f"{levenshtein(r.name, pop_name)} edit(s) from '{pop_name}'", pop))
        elif any(r.name == pop_name + s or r.name == s.strip("-") + "-" + pop_name for s in SUFFIXES):
            out.append(Suspicion("popular name plus a trust-suggesting word", pop))
    return out


@dataclass(frozen=True)
class Policy:
    allowed_registries: tuple[str, ...]
    popular: tuple[str, ...]
    require_digest: bool = True

    @staticmethod
    def load(path: Path) -> "Policy":
        d = json.loads(Path(path).read_text())
        return Policy(tuple(d["allowed_registries"]), tuple(d["popular"]), d.get("require_digest", True))


def evaluate(ref: str, policy: Policy) -> list[str]:
    r = parse(ref)
    problems = []
    if r.registry not in policy.allowed_registries:
        problems.append(f"registry {r.registry} is not on the allowlist")
    for s in check_name(ref, list(policy.popular)):
        problems.append(f"possible typosquat of {s.looks_like}: {s.reason}")
    if policy.require_digest and not DIGEST.search(ref):
        problems.append("not pinned by digest")
    return problems
