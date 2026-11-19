"""Dependency resolver simulation: diamond conflicts, resolution strategies, security trade-offs.

Two installer styles are modelled:
  * flat   (pip-like): one version per package; conflicting ranges are an ERROR.
  * nested (npm-like): each dependent may get its own copy; conflicts become DUPLICATES.
Real resolvers (pip's resolvelib, npm arborist, Cargo, Go MVS, Maven "nearest wins") differ
in detail; this is a teaching model over a fixture registry. Version syntax is a small
semver-like subset: ^ ~ * == >= > <= < and "||".
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


# --- versions and ranges -----------------------------------------------------

def parse_v(s: str) -> tuple[int, int, int]:
    parts = [int(x) for x in s.split(".")]
    return tuple((parts + [0, 0, 0])[:3])  # type: ignore[return-value]


def _comparators(token: str) -> list[tuple[str, tuple[int, int, int]]]:
    token = token.strip()
    if token in ("*", ""):
        return [(">=", (0, 0, 0))]
    if token.startswith("^"):
        lo = parse_v(token[1:])
        if lo[0] > 0:
            hi = (lo[0] + 1, 0, 0)
        elif lo[1] > 0:
            hi = (0, lo[1] + 1, 0)
        else:
            hi = (0, 0, lo[2] + 1)
        return [(">=", lo), ("<", hi)]
    if token.startswith("~"):
        lo = parse_v(token[1:])
        return [(">=", lo), ("<", (lo[0], lo[1] + 1, 0))]
    for op in (">=", "<=", "==", ">", "<", "="):
        if token.startswith(op):
            return [("==" if op == "=" else op, parse_v(token[len(op):]))]
    return [("==", parse_v(token))]


def satisfies(version: str, spec: str) -> bool:
    v = parse_v(version)
    ops = {">=": lambda a, b: a >= b, ">": lambda a, b: a > b, "<=": lambda a, b: a <= b,
           "<": lambda a, b: a < b, "==": lambda a, b: a == b}
    for alt in spec.split("||"):
        tokens = alt.replace(",", " ").split()
        comps = [c for t in (tokens or ["*"]) for c in _comparators(t)]
        if all(ops[op](v, bound) for op, bound in comps):
            return True
    return False


# --- registry ----------------------------------------------------------------

class Registry:
    def __init__(self, data: dict):
        self.packages = data["packages"]
        self.advisories = data.get("advisories", [])

    def versions(self, name: str) -> list[str]:
        return sorted(self.packages[name]["versions"], key=parse_v, reverse=True)

    def deps(self, name: str, ver: str) -> dict:
        return dict(self.packages[name]["versions"][ver].get("deps", {}))

    def integrity(self, name: str, ver: str) -> str:
        meta = self.packages[name]["versions"][ver]
        return meta.get("integrity") or "sha256-" + hashlib.sha256(f"{name}@{ver}".encode()).hexdigest()[:16]


@dataclass
class Conflict:
    package: str
    constraints: list[tuple[str, str]]

    def explain(self) -> str:
        who = "; ".join(f"{src} needs {spec}" for src, spec in self.constraints)
        return f"no version of {self.package} satisfies all of: {who}"


@dataclass
class Resolution:
    ok: bool
    versions: dict = field(default_factory=dict)          # flat: name -> version
    installed: list = field(default_factory=list)         # nested: list of (name, version)
    conflicts: list = field(default_factory=list)
    violated: list = field(default_factory=list)          # (dependent, dep, declared_spec, chosen)

    def pairs(self) -> list[tuple[str, str]]:
        return sorted(self.installed or self.versions.items())

    def duplicates(self) -> dict:
        seen: dict[str, set] = {}
        for n, v in self.pairs():
            seen.setdefault(n, set()).add(v)
        return {n: sorted(vs, key=parse_v) for n, vs in seen.items() if len(vs) > 1}


# --- resolvers ---------------------------------------------------------------

def resolve_flat(reg: Registry, root: dict, pins: dict | None = None,
                 overrides: dict | None = None) -> Resolution:
    """One version per package. `pins` ADD a constraint (pip constraints file);
    `overrides` REPLACE what dependents asked for (npm overrides / yarn resolutions)."""
    overrides = overrides or {}
    last_conflict: list[Conflict] = []

    start: dict[str, list] = {}
    for name, spec in root.items():
        start.setdefault(name, []).append(("root", overrides.get(name, spec)))
    for name, ver in (pins or {}).items():
        start.setdefault(name, []).append(("pin", f"=={ver}"))

    def solve(chosen: dict, cons: dict):
        pending = sorted(n for n in cons if n not in chosen)
        if not pending:
            return chosen
        name = pending[0]
        if name not in reg.packages:
            last_conflict[:] = [Conflict(name, list(cons[name]))]
            return None
        candidates = [v for v in reg.versions(name) if all(satisfies(v, s) for _, s in cons[name])]
        if not candidates:
            last_conflict[:] = [Conflict(name, list(cons[name]))]
            return None
        for v in candidates:
            new_cons = {k: list(x) for k, x in cons.items()}
            ok = True
            for dep, spec in reg.deps(name, v).items():
                spec = overrides.get(dep, spec)
                new_cons.setdefault(dep, []).append((f"{name}@{v}", spec))
                if dep in chosen and not satisfies(chosen[dep], spec):
                    last_conflict[:] = [Conflict(dep, list(new_cons[dep]))]
                    ok = False
            if not ok:
                continue
            result = solve({**chosen, name: v}, new_cons)
            if result is not None:
                return result
        return None

    result = solve({}, start)
    if result is None:
        return Resolution(False, conflicts=list(last_conflict))
    res = Resolution(True, versions=result)
    res.violated = _violations(reg, root, result)
    return res


def _violations(reg: Registry, root: dict, chosen: dict) -> list:
    out = []
    for dep, spec in root.items():
        if dep in chosen and not satisfies(chosen[dep], spec):
            out.append(("root", dep, spec, chosen[dep]))
    for name, ver in chosen.items():
        for dep, spec in reg.deps(name, ver).items():
            if dep in chosen and not satisfies(chosen[dep], spec):
                out.append((f"{name}@{ver}", dep, spec, chosen[dep]))
    return out


def resolve_nested(reg: Registry, root: dict) -> Resolution:
    """npm-style: every requirement gets the highest version matching ITS OWN range."""
    installed: set[tuple[str, str]] = set()
    conflicts: list[Conflict] = []

    def install(name: str, spec: str, source: str):
        cands = [v for v in reg.versions(name) if satisfies(v, spec)] if name in reg.packages else []
        if not cands:
            conflicts.append(Conflict(name, [(source, spec)]))
            return
        ver = cands[0]
        if (name, ver) in installed:
            return
        installed.add((name, ver))
        for dep, dspec in reg.deps(name, ver).items():
            install(dep, dspec, f"{name}@{ver}")

    for name, spec in root.items():
        install(name, spec, "root")
    return Resolution(not conflicts, installed=sorted(installed), conflicts=conflicts)


# --- security ----------------------------------------------------------------

def audit(reg: Registry, res: Resolution) -> list[dict]:
    hits = []
    for name, ver in res.pairs():
        for adv in reg.advisories:
            if adv["package"] == name and satisfies(ver, adv["affected"]):
                hits.append({"package": name, "version": ver, "id": adv["id"], "severity": adv["severity"]})
    return hits


# --- lockfiles, vendoring ----------------------------------------------------

class LockfileError(Exception):
    pass


def make_lockfile(reg: Registry, res: Resolution) -> dict:
    return {"lockfileVersion": 1,
            "packages": [{"name": n, "version": v, "integrity": reg.integrity(n, v)} for n, v in res.pairs()]}


def install_from_lockfile(reg: Registry, lock: dict) -> Resolution:
    """Install EXACTLY what the lock says, and fail if the registry content changed."""
    pairs = []
    for p in lock["packages"]:
        n, v = p["name"], p["version"]
        if n not in reg.packages or v not in reg.packages[n]["versions"]:
            raise LockfileError(f"{n}@{v} is not in the registry")
        if reg.integrity(n, v) != p["integrity"]:
            raise LockfileError(f"integrity mismatch for {n}@{v}: the published artifact changed")
        pairs.append((n, v))
    return Resolution(True, installed=sorted(pairs))


def lock_satisfies(root: dict, lock: dict) -> list[str]:
    """Return the root requirements the lock no longer satisfies (drift)."""
    have = {p["name"]: p["version"] for p in lock["packages"]}
    return [n for n, spec in root.items() if n not in have or not satisfies(have[n], spec)]


def vendor(res: Resolution) -> dict:
    """Copy the sources into the repo. Fixed content, but no automatic updates or advisories."""
    return {n: {"version": v, "vendored": True} for n, v in res.pairs()}


def vendored_staleness(reg: Registry, vendored: dict) -> list[str]:
    return [f"{n}: vendored {m['version']}, registry has {reg.versions(n)[0]}"
            for n, m in vendored.items() if parse_v(reg.versions(n)[0]) > parse_v(m["version"])]


# --- compare strategies ------------------------------------------------------

def suggest_upgrades(reg: Registry, root: dict, package: str) -> list[str]:
    """Which versions of `package` (a root dependency) make the whole tree resolve with no violations?"""
    good = []
    for v in reg.versions(package):
        trial = dict(root)
        trial[package] = f"=={v}"
        r = resolve_flat(reg, trial)
        if r.ok and not r.violated:
            good.append(v)
    return good


def compare_strategies(reg: Registry, root: dict, lib: str, old_pin: str, new_range: str,
                       upgrade_pkg: str) -> list[dict]:
    rows = []

    def add(label, res, note):
        vuln = audit(reg, res) if res.ok else []
        rows.append({"strategy": label, "ok": res.ok, "vulnerable": len(vuln),
                     "violated_ranges": len(res.violated), "duplicates": len(res.duplicates()),
                     "note": note if res.ok else res.conflicts[0].explain()})

    add("plain flat resolve (pip-style)", resolve_flat(reg, root), "")
    add("nested install (npm-style)", resolve_nested(reg, root),
        "both major versions installed; the vulnerable copy is still shipped")
    add(f"pin {lib}=={old_pin} (constraint)", resolve_flat(reg, root, pins={lib: old_pin}), "")
    add(f"override {lib} -> {old_pin}", resolve_flat(reg, root, overrides={lib: f"=={old_pin}"}),
        "forces the old, vulnerable version on a dependent that needs the new one")
    add(f"override {lib} -> {new_range}", resolve_flat(reg, root, overrides={lib: new_range}),
        "secure version, but a dependent runs outside its declared range: test it")
    ups = suggest_upgrades(reg, root, upgrade_pkg)
    if ups:
        trial = dict(root)
        trial[upgrade_pkg] = f"=={ups[0]}"
        add(f"upgrade {upgrade_pkg} to {ups[0]}", resolve_flat(reg, trial),
            "the clean fix: the maintainer already supports the new range")
    return rows
