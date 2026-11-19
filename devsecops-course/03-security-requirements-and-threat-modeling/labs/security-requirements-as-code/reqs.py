"""Security requirements as code: a YAML catalog mapped to automated checks and a CI gate.

The gate fails when an in-scope requirement has NO check, or its check FAILS.
Standard library plus PyYAML. Nothing is executed except small check functions.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

CHECKS: dict[str, Callable[[dict], tuple[bool, str]]] = {}


def check(name: str):
    """Decorator: register a function as the automated check called `name` in the catalog."""
    def deco(fn):
        CHECKS[name] = fn
        return fn
    return deco


def _get(cfg: dict, path: str, default=None):
    cur = cfg
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


@check("password_min_length")
def _pw_len(cfg):
    n = _get(cfg, "password.min_length", 0)
    return n >= 12, f"min_length={n}"


@check("breached_password_check")
def _breached(cfg):
    v = _get(cfg, "password.breached_check", False)
    return v is True, f"breached_check={v}"


@check("cookie_flags")
def _cookie(cfg):
    s, h = _get(cfg, "session.cookie_secure", False), _get(cfg, "session.cookie_httponly", False)
    return bool(s and h), f"secure={s} httponly={h}"


@check("idle_timeout")
def _idle(cfg):
    t = _get(cfg, "session.idle_timeout_min", 10**6)
    return t <= 30, f"idle_timeout_min={t}"


@check("tls_min_version")
def _tls(cfg):
    v = str(_get(cfg, "tls.min_version", "1.0"))
    return tuple(int(x) for x in v.split(".")) >= (1, 2), f"min_version={v}"


@check("security_headers")
def _headers(cfg):
    h = _get(cfg, "headers", {})
    missing = [x for x in ("Content-Security-Policy", "X-Content-Type-Options") if x not in h]
    return not missing, ("missing=" + ",".join(missing)) if missing else "all present"


@check("auth_logging")
def _logging(cfg):
    events, pw = _get(cfg, "logging.log_auth_events", False), _get(cfg, "logging.log_passwords", True)
    return bool(events and not pw), f"log_auth_events={events} log_passwords={pw}"


@check("deny_by_default")
def _deny(cfg):
    v = _get(cfg, "authz.deny_by_default", False)
    return v is True, f"deny_by_default={v}"


@check("password_hash")
def _hash(cfg):
    v = _get(cfg, "password.hash", "none")
    return v in {"argon2id", "bcrypt", "scrypt", "pbkdf2"}, f"hash={v}"


@dataclass
class Result:
    id: str
    title: str
    level: int
    status: str   # PASS | FAIL | NO_TEST | OUT_OF_SCOPE
    detail: str


def load_catalog(path: Path) -> dict:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    ids = [r["id"] for r in data["requirements"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate requirement id")
    return data


def load_config(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evaluate(catalog: dict, cfg: dict, checks: dict | None = None) -> list[Result]:
    checks = CHECKS if checks is None else checks
    target = catalog.get("target_level", 1)
    out = []
    for r in catalog["requirements"]:
        if r["level"] > target:
            out.append(Result(r["id"], r["title"], r["level"], "OUT_OF_SCOPE", f"level {r['level']} > target {target}"))
            continue
        fn = checks.get(r.get("check", ""))
        if fn is None:
            out.append(Result(r["id"], r["title"], r["level"], "NO_TEST", "no automated check registered"))
            continue
        ok, detail = fn(cfg)
        out.append(Result(r["id"], r["title"], r["level"], "PASS" if ok else "FAIL", detail))
    return out


def gate(results: list[Result]) -> int:
    """0 only when every in-scope requirement has a passing test."""
    return 0 if all(r.status in ("PASS", "OUT_OF_SCOPE") for r in results) else 1


def traceability(catalog: dict, results: list[Result]) -> dict[str, list[str]]:
    """threat -> requirement ids with status, so every threat shows as covered or not."""
    by_id = {r.id: r for r in results}
    out: dict[str, list[str]] = {}
    for r in catalog["requirements"]:
        out.setdefault(r["threat"], []).append(f"{r['id']}:{by_id[r['id']].status}")
    return out


def render(results: list[Result]) -> str:
    return "\n".join(f"{r.status:13} {r.id:13} L{r.level} {r.title}  [{r.detail}]" for r in results)
