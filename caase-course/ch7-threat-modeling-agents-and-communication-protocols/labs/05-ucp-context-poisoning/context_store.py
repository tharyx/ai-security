"""Poisoning a shared context store to influence downstream agents (Chapter 7, lab 5).

"UCP-style shared context store (course term)". The syllabus calls this a "Unified Context Protocol", but no
standard with that name was found. The real UCP is Google's Universal Commerce Protocol (agentic commerce).
This lab implements the CONCEPT the syllabus describes: several agents and an orchestrator read and write one
shared context store.

Two attacks by a low-trust agent (the support agent, which reads customer tickets):
  1. VALUE poisoning:       writes pricing/approved_discount = 100 so the pricing agent gives everything away
  2. INSTRUCTION poisoning: writes a note that contains an "INSTRUCTION:" line; a naive downstream agent obeys it
Secure store layers (flags):
  acl         - per-namespace writer allow-list (support may write notes/ only)
  signed      - every entry carries the writer id and an HMAC with the WRITER's key; verified on every read
  trust_tag   - entries carry a trust tier; instructions are only honoured from trusted tiers
  ttl         - entries expire (limits persistence of poison)
"""
from __future__ import annotations

import hashlib
import hmac
import json

TRUST = {"support-agent": "low", "pricing-admin": "high", "orchestrator": "high"}
KEYS = {"support-agent": b"FAKE-k-support", "pricing-admin": b"FAKE-k-pricing", "orchestrator": b"FAKE-k-orch"}
ACL = {"pricing/": {"pricing-admin"}, "notes/": {"support-agent", "orchestrator", "pricing-admin"}}


class StoreError(Exception):
    pass


def _sig(writer: str, key: str, value, ts: float) -> str:
    raw = json.dumps({"w": writer, "k": key, "v": value, "ts": ts}, sort_keys=True).encode()
    return hmac.new(KEYS[writer], raw, hashlib.sha256).hexdigest()


class ContextStore:
    def __init__(self, *, acl=False, signed=False, trust_tag=False, ttl: float | None = None, clock=None):
        self.acl, self.signed, self.trust_tag, self.ttl = acl, signed, trust_tag, ttl
        self.clock = clock or (lambda: 1_800_000_000.0)
        self.raw: dict[str, dict] = {}

    def put(self, writer: str, key: str, value) -> None:
        if self.acl:
            allowed = next((w for prefix, w in ACL.items() if key.startswith(prefix)), set())
            if writer not in allowed:
                raise StoreError(f"{writer} may not write {key}")
        ts = self.clock()
        entry = {"value": value, "writer": writer, "ts": ts}
        if self.signed:
            entry["sig"] = _sig(writer, key, value, ts)
        self.raw[key] = entry

    def get(self, key: str) -> dict:
        e = self.raw.get(key)
        if e is None:
            raise KeyError(key)
        if self.ttl is not None and self.clock() - e["ts"] > self.ttl:
            raise StoreError(f"{key} expired")
        if self.signed:
            if e["writer"] not in KEYS or not hmac.compare_digest(e.get("sig", ""), _sig(e["writer"], key, e["value"], e["ts"])):
                raise StoreError(f"{key}: bad entry signature")
        out = dict(e)
        out["trust"] = TRUST.get(e["writer"], "none") if self.trust_tag else "unknown"
        return out


class Sink:
    """Where a harmless 'exfiltration' lands in tests."""

    def __init__(self):
        self.items: list[str] = []


class PricingAgent:
    """Downstream agent 1: applies the discount from the store."""

    def __init__(self, store: ContextStore):
        self.store = store

    def quote(self, price: float) -> float:
        try:
            pct = float(self.store.get("pricing/approved_discount")["value"])
        except (KeyError, StoreError, ValueError):
            pct = 0.0
        pct = max(0.0, min(pct, 100.0))
        return round(price * (1 - pct / 100), 2)


class NaiveWorker:
    """Downstream agent 2: reads notes and obeys 'INSTRUCTION:' lines. Hardened when honour_low=False."""

    def __init__(self, store: ContextStore, sink: Sink, secret: str, honour_low: bool = True):
        self.store, self.sink, self.secret, self.honour_low = store, sink, secret, honour_low

    def run(self, note_keys: list[str]) -> list[str]:
        done = []
        for k in note_keys:
            try:
                e = self.store.get(k)
            except (KeyError, StoreError):
                continue
            if e["trust"] == "low" and not self.honour_low:
                continue  # low-trust text is DATA: summarised, never executed
            for line in str(e["value"]).splitlines():
                if line.startswith("INSTRUCTION:") and "send secret" in line:
                    self.sink.items.append(self.secret)
                    done.append(line)
        return done


def render_context(store: ContextStore, keys: list[str]) -> str:
    """How a prompt builder should show entries: quoted, labelled, with provenance."""
    parts = []
    for k in keys:
        try:
            e = store.get(k)
        except (KeyError, StoreError):
            continue
        parts.append(f'<context key="{k}" writer="{e["writer"]}" trust="{e["trust"]}">\n{e["value"]}\n</context>')
    return "\n".join(parts)
