"""Structured tool-invocation logging, anomaly detections, and a signed hash-chained audit trail.

One JSON record per tools/call with FULL CONTEXT:
    ts, seq, event_id, session_id, user, client_id, server, tool,
    args_hash (SHA-256 of the canonical raw arguments: proves what was sent without storing it),
    args_redacted (the arguments with secrets masked), result_size, latency_ms, decision (allow|deny|error), reason.

Audit chain (non-repudiation helper): each record carries prev_hash and hash = SHA-256(prev_hash + canonical record),
and sig = HMAC-SHA256(audit_key, hash). Editing, deleting, re-ordering or forging records breaks verify().
Cutting records off the END is caught only if you keep the last hash/count somewhere else (the "anchor").
Lab simplification: real systems use an asymmetric signature (Ed25519 or a KMS key) so verifiers cannot forge,
and ship records to write-once storage or a transparency log. HMAC keeps the lab dependency-free.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

GENESIS = "0" * 64
SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "ssn", "card"}
SECRET_PATTERNS = [re.compile(p) for p in (r"hvs\.[A-Za-z0-9_-]{8,}", r"sk-[A-Za-z0-9]{12,}", r"AKIA[0-9A-Z]{16}",
                                           r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")]


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def redact(value: Any, key: str = "") -> Any:
    """Mask sensitive keys and secret-looking strings, recursively. Returns a new object."""
    if key.lower() in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        for p in SECRET_PATTERNS:
            value = p.sub("[REDACTED]", value)
        return value if len(value) <= 200 else value[:200] + "...[truncated]"
    return value


# ---------------------------------------------------------------------------------- the chain

class AuditChain:
    def __init__(self, key: bytes) -> None:
        self.key = key
        self.records: list[dict[str, Any]] = []

    @property
    def last_hash(self) -> str:
        return self.records[-1]["hash"] if self.records else GENESIS

    def append(self, body: dict[str, Any]) -> dict[str, Any]:
        rec = dict(body, seq=len(self.records) + 1, prev_hash=self.last_hash)
        rec["hash"] = sha256(rec["prev_hash"] + canonical(rec))
        rec["sig"] = hmac.new(self.key, rec["hash"].encode(), hashlib.sha256).hexdigest()
        self.records.append(rec)
        return rec

    def anchor(self) -> dict[str, Any]:
        """Publish this somewhere else (another system, a ticket, a transparency log) to detect truncation."""
        return {"count": len(self.records), "last_hash": self.last_hash}


def verify(records: list[dict[str, Any]], key: bytes, anchor: dict[str, Any] | None = None) -> list[str]:
    """Return a list of problems. An empty list means the chain is intact."""
    problems: list[str] = []
    prev = GENESIS
    for i, rec in enumerate(records, 1):
        body = {k: v for k, v in rec.items() if k not in ("hash", "sig")}
        if rec.get("seq") != i:
            problems.append(f"record {i}: sequence number is {rec.get('seq')} (deleted or re-ordered records)")
        if rec.get("prev_hash") != prev:
            problems.append(f"record {i}: prev_hash does not match the previous record")
        if sha256(rec.get("prev_hash", "") + canonical(body)) != rec.get("hash"):
            problems.append(f"record {i}: content was changed (hash mismatch)")
        good_sig = hmac.new(key, str(rec.get("hash")).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(good_sig, str(rec.get("sig"))):
            problems.append(f"record {i}: signature invalid (forged or re-hashed without the key)")
        prev = rec.get("hash", prev)
    if anchor:
        if len(records) != anchor["count"] or (records and records[-1].get("hash") != anchor["last_hash"]):
            problems.append("anchor mismatch: records were cut off the end or appended after the anchor")
    return problems


# ---------------------------------------------------------------------------------- the logger

@dataclass
class InvocationLogger:
    chain: AuditChain
    clock: Callable[[], float] = time.time
    sink: list[str] = field(default_factory=list)       # one JSON line per event (what you would ship to a SIEM)
    _n: int = 0

    def record(self, *, session_id: str, user: str, client_id: str, server: str, tool: str, args: dict[str, Any],
               result: Any, latency_ms: float, decision: str, reason: str = "") -> dict[str, Any]:
        self._n += 1
        size = len(result) if isinstance(result, (str, bytes)) else len(canonical(result)) if result is not None else 0
        body = {
            "ts": round(self.clock(), 3), "event_id": f"ev-{self._n:06d}", "session_id": session_id, "user": user,
            "client_id": client_id, "server": server, "tool": tool, "args_hash": sha256(canonical(args)),
            "args_redacted": redact(args), "result_size": size, "latency_ms": round(latency_ms, 1),
            "decision": decision, "reason": reason,
        }
        rec = self.chain.append(body)
        self.sink.append(canonical(rec))
        return rec


@dataclass
class Identity:
    user: str
    client_id: str
    session_id: str


class LoggedCaller:
    """Wrap any ``call(server, tool, args) -> result`` so that EVERY outcome is logged, including denials and errors."""

    def __init__(self, call: Callable[[str, str, dict], Any], logger: InvocationLogger,
                 allow: Callable[[Identity, str, str], str | None] | None = None,
                 timer: Callable[[], float] = time.perf_counter) -> None:
        self.call, self.logger, self.allow, self.timer = call, logger, allow, timer

    def __call__(self, who: Identity, server: str, tool: str, args: dict) -> Any:
        t0 = self.timer()
        decision, reason, result = "allow", "", None
        try:
            denial = self.allow(who, server, tool) if self.allow else None
            if denial:
                decision, reason = "deny", denial
                raise PermissionError(denial)
            result = self.call(server, tool, args)
            return result
        except PermissionError:
            raise
        except Exception as exc:
            decision, reason = "error", type(exc).__name__          # class name only: messages may hold secrets
            raise
        finally:
            self.logger.record(session_id=who.session_id, user=who.user, client_id=who.client_id, server=server, tool=tool,
                               args=args, result=result, latency_ms=(self.timer() - t0) * 1000, decision=decision, reason=reason)


# ---------------------------------------------------------------------------------- detections

@dataclass
class DetectionConfig:
    burst_calls: int = 20              # calls ...
    burst_window_s: float = 10.0       # ... within this many seconds, per user
    deny_threshold: int = 3            # denials within the window
    large_result: int = 100_000        # bytes
    egress_window_s: float = 60.0      # sensitive read followed by egress within this time
    tool_tags: dict[str, str] = field(default_factory=lambda: {"read_secret": "sensitive_read", "read_customers": "sensitive_read",
                                                                 "send_email": "egress", "http_post": "egress"})
    baseline_tools: dict[str, set[str]] = field(default_factory=dict)    # user -> tools seen in the learning period
    business_hours_utc: tuple[int, int] = (6, 20)


def detect(records: list[dict[str, Any]], cfg: DetectionConfig | None = None) -> list[dict[str, Any]]:
    cfg = cfg or DetectionConfig()
    alerts: list[dict[str, Any]] = []

    def alert(rule: str, sev: str, user: str, evidence: list[str], note: str) -> None:
        alerts.append({"rule": rule, "severity": sev, "user": user, "evidence": evidence, "note": note})

    by_user: dict[str, list[dict]] = {}
    for r in records:
        by_user.setdefault(r["user"], []).append(r)
    for user, recs in by_user.items():
        recs = sorted(recs, key=lambda r: r["ts"])
        # 1. burst
        for i, r in enumerate(recs):
            window = [x for x in recs[i:] if x["ts"] - r["ts"] <= cfg.burst_window_s]
            if len(window) >= cfg.burst_calls:
                alert("burst", "medium", user, [x["event_id"] for x in window[:5]], f"{len(window)} calls in {cfg.burst_window_s}s")
                break
        # 2. repeated denials
        denies = [r for r in recs if r["decision"] == "deny"]
        for i, r in enumerate(denies):
            window = [x for x in denies[i:] if x["ts"] - r["ts"] <= cfg.burst_window_s * 6]
            if len(window) >= cfg.deny_threshold:
                alert("repeated_denials", "high", user, [x["event_id"] for x in window], "probing for tools or scopes it may not use")
                break
        # 3. new tool outside baseline
        base = cfg.baseline_tools.get(user)
        if base is not None:
            for r in recs:
                if r["tool"] not in base and r["decision"] == "allow":
                    alert("new_tool", "low", user, [r["event_id"]], f"first use of {r['server']}.{r['tool']}")
                    base = base | {r["tool"]}
        # 4. large result
        for r in recs:
            if r["result_size"] >= cfg.large_result:
                alert("large_result", "medium", user, [r["event_id"]], f"{r['result_size']} bytes from {r['tool']}")
        # 5. sensitive read followed by egress (possible exfiltration chain)
        for i, r in enumerate(recs):
            if cfg.tool_tags.get(r["tool"]) == "sensitive_read" and r["decision"] == "allow":
                for x in recs[i + 1:]:
                    if x["ts"] - r["ts"] > cfg.egress_window_s:
                        break
                    if cfg.tool_tags.get(x["tool"]) == "egress" and x["decision"] == "allow":
                        alert("read_then_egress", "high", user, [r["event_id"], x["event_id"]], f"{r['tool']} then {x['tool']} within {cfg.egress_window_s}s")
                        break
        # 6. secrets seen in arguments
        for r in recs:
            if "[REDACTED]" in canonical(r["args_redacted"]):
                alert("secret_in_args", "medium", user, [r["event_id"]], "a secret-like value was passed as a tool argument")
        # 7. off-hours
        lo, hi = cfg.business_hours_utc
        for r in recs:
            hour = int(time.gmtime(r["ts"]).tm_hour)
            if not lo <= hour < hi and r["decision"] == "allow":
                alert("off_hours", "low", user, [r["event_id"]], f"call at {hour:02d}:00 UTC")
                break
    return alerts
