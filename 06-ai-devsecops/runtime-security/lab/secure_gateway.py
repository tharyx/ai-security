"""The same model-serving gateway, rebuilt with runtime security layers.

Each layer can be switched off with a flag, so tests can prove which layer stops which attack.

    L1  Authentication: hashed client keys map to a principal (id, team, tenant).
        Identity never comes from the request body or from headers.               (hard)
    L2  Model access control: a team may only call the deployments it is entitled to. (hard)
    L3  Limits: payload size, max_tokens cap, token buckets per principal AND per
        tenant, and a token quota per team.                                          (hard)
    L4  Secrets management: the provider key lives in a vault stand-in, is read at
        call time (so rotation works), and never enters a prompt.                    (hard)
    L5  Input guard: an injection heuristic that FLAGS requests for monitoring.       (soft)
    L6  Output guard: blocks any response that contains a known secret or canary.     (hard)
    L7  Redacted logs: one structured line per request, with a prompt hash and
        length instead of the prompt, and secret patterns masked.                    (hard)
    L8  Telemetry: OpenTelemetry-style spans with GenAI-style attributes, exported
        as dicts that ``monitor.py`` reads.                                           (detect)

Everything is in-process and offline. ``FakeProvider`` plays the hosted model API.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

from aisec_lab import LLM, get_llm

Clock = Callable[[], float]


def rough_tokens(text: str) -> int:
    """About four characters per token for English text."""
    return max(1, len(text) // 4)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def fingerprint(secret: str) -> str:
    """A short, non-reversible ID for a secret. Safe to log; the secret is not."""
    return "fp:" + sha256_hex(secret)[:10]


# --------------------------------------------------------------------------- the "provider"

@dataclass
class FakeProvider:
    """A hosted model API. It accepts only keys it currently considers valid."""

    llm: LLM = field(default_factory=get_llm)
    valid_keys: set[str] = field(default_factory=set)
    calls: list[dict] = field(default_factory=list)   # what reached the provider (key fingerprint only)

    def issue(self, key: str) -> None:
        self.valid_keys.add(key)

    def revoke(self, key: str) -> None:
        self.valid_keys.discard(key)

    def complete(self, messages: list[dict], *, api_key: str) -> str:
        if api_key not in self.valid_keys:
            raise PermissionError("invalid or revoked provider key")
        self.calls.append({"key": fingerprint(api_key), "messages": len(messages)})
        return self.llm.complete(messages)


# --------------------------------------------------------------------------- L4 secrets

@dataclass
class SecretStore:
    """A vault stand-in: versioned secrets, audited reads, rotation with a grace period.

    Real systems: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager,
    injected into pods by the Secrets Store CSI driver or External Secrets.
    """

    clock: Clock = time.monotonic
    _versions: dict[str, list[dict]] = field(default_factory=dict)
    access_log: list[dict] = field(default_factory=list)   # who read what, never the value

    def put(self, name: str, value: str) -> int:
        versions = self._versions.setdefault(name, [])
        versions.append({"version": len(versions) + 1, "value": value, "created": self.clock(), "active": True})
        return len(versions)

    def get(self, name: str, *, accessor: str) -> str:
        current = [v for v in self._versions.get(name, []) if v["active"]]
        if not current:
            raise KeyError(f"no active version of secret {name!r}")
        latest = current[-1]
        self.access_log.append({"secret": name, "version": latest["version"], "accessor": accessor,
                                "at": self.clock()})
        return latest["value"]

    def rotate(self, name: str, new_value: str) -> int:
        """Add a new version. Old versions stay readable until ``retire`` (the grace period)."""
        return self.put(name, new_value)

    def retire(self, name: str, version: int) -> None:
        for v in self._versions.get(name, []):
            if v["version"] == version:
                v["active"] = False

    def all_values(self) -> list[str]:
        """Every version ever stored. The output guard and the redactor use this list."""
        return [v["value"] for versions in self._versions.values() for v in versions]


# --------------------------------------------------------------------------- L1 / L2 identity and entitlements

@dataclass(frozen=True)
class Principal:
    id: str
    team: str
    tenant: str


@dataclass(frozen=True)
class Deployment:
    name: str
    model: str
    data_class: str = "internal"        # the most sensitive data this deployment may see
    max_output_tokens: int = 512


# --------------------------------------------------------------------------- L3 limits

@dataclass
class Limits:
    max_prompt_chars: int = 8000
    principal_burst: int = 5            # token bucket per principal
    principal_refill_per_sec: float = 0.5
    tenant_burst: int = 20              # a second bucket for the whole tenant
    tenant_refill_per_sec: float = 2.0
    team_token_quota: dict[str, int] = field(default_factory=dict)   # tokens per period; missing = 0
    default_team_quota: int = 0


@dataclass
class TokenBucket:
    capacity: int
    refill_per_sec: float
    clock: Clock
    _state: dict[str, tuple[float, float]] = field(default_factory=dict)

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = self.clock()
        tokens, last = self._state.get(key, (float(self.capacity), now))
        tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
        ok = tokens >= cost
        self._state[key] = (tokens - cost if ok else tokens, now)
        return ok


# --------------------------------------------------------------------------- L5 / L6 / L7 guards and redaction

INJECTION_HINTS = re.compile(
    r"ignore (all |any )?(previous|prior|above) instructions|disregard (previous|prior|earlier) instructions"
    r"|system prompt|developer mode|api[_ ]?key|reveal .*(secret|key|token)", re.I)

SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{6,}"),           # provider-style keys (lab format)
    re.compile(r"\bgw-[A-Za-z0-9_-]{6,}"),           # gateway client keys (lab format)
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),             # AWS access key ID shape
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]+=*", re.I),
    re.compile(r"\bCANARY-[0-9a-f]{6,}\b"),
]
# Output guard: platform credentials only. A user's own pasted data is redacted in logs, not blocked.
OUTPUT_SECRET_PATTERNS = SECRET_PATTERNS[:3] + [SECRET_PATTERNS[4]]
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def redact(text: str, known_secrets: list[str] | tuple[str, ...] = ()) -> str:
    """Mask known secret values first (exact match), then anything that looks like one."""
    for value in sorted(known_secrets, key=len, reverse=True):
        if value:
            text = text.replace(value, "[REDACTED:" + fingerprint(value) + "]")
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return EMAIL.sub("[EMAIL]", text)


# --------------------------------------------------------------------------- L8 telemetry

@dataclass
class Span:
    """A tiny OpenTelemetry-like span. Attribute names follow the GenAI semantic
    conventions where one exists (``gen_ai.*``); ``aisec.*`` names are this lab's own."""

    trace_id: str
    span_id: str
    parent_id: str | None
    name: str
    start: float
    end: float | None = None
    status: str = "OK"                     # OK | ERROR
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict] = field(default_factory=list)

    def set(self, **attrs: Any) -> "Span":
        self.attributes.update({k.replace("__", "."): v for k, v in attrs.items()})
        return self

    def to_dict(self) -> dict:
        return {"trace_id": self.trace_id, "span_id": self.span_id, "parent_id": self.parent_id,
                "name": self.name, "start": self.start, "end": self.end, "status": self.status,
                "attributes": dict(self.attributes), "events": list(self.events)}


@dataclass
class Tracer:
    clock: Clock
    spans: list[Span] = field(default_factory=list)

    def start(self, name: str, parent: Span | None = None) -> Span:
        span = Span(trace_id=parent.trace_id if parent else secrets.token_hex(8),
                    span_id=secrets.token_hex(4), parent_id=parent.span_id if parent else None,
                    name=name, start=self.clock())
        self.spans.append(span)
        return span

    def end(self, span: Span, status: str = "OK") -> None:
        span.end, span.status = self.clock(), status

    def export(self) -> list[dict]:
        return [s.to_dict() for s in self.spans]


# --------------------------------------------------------------------------- the gateway

SYSTEM_PROMPT = ("You are the ACME support assistant. Answer briefly. "
                 "Tool access is handled by the platform, not by you.")


@dataclass
class SecureModelGateway:
    provider: FakeProvider
    secrets: SecretStore
    clients: dict[str, Principal]                 # sha256(client key) -> principal
    deployments: dict[str, Deployment]
    entitlements: dict[str, set[str]]             # team -> deployment names
    limits: Limits = field(default_factory=Limits)
    clock: Clock = time.monotonic
    provider_secret_name: str = "provider/api-key"
    canaries: tuple[str, ...] = ()
    # Layer switches: turn one off to see what the others still catch.
    enforce_auth: bool = True
    enforce_entitlements: bool = True
    enforce_limits: bool = True
    keep_secrets_out_of_prompt: bool = True
    input_guard: bool = True
    output_guard: bool = True
    redact_logs: bool = True

    def __post_init__(self) -> None:
        self.tracer = Tracer(self.clock)
        self.log_lines: list[str] = []
        self.used_tokens: dict[str, int] = defaultdict(int)          # per team
        self._p_bucket = TokenBucket(self.limits.principal_burst, self.limits.principal_refill_per_sec, self.clock)
        self._t_bucket = TokenBucket(self.limits.tenant_burst, self.limits.tenant_refill_per_sec, self.clock)
        self._known_hashes = {h: p for h, p in self.clients.items()}

    # ---- helpers
    def revoke_client(self, client_key: str) -> None:
        self._known_hashes.pop(sha256_hex(client_key), None)

    def _authenticate(self, req: dict) -> Principal | None:
        key = str(req.get("api_key") or "")
        if not self.enforce_auth:   # what the vulnerable gateway does: trust the body
            return Principal(id=str(req.get("user", "anonymous")), team=str(req.get("team", "unknown")),
                             tenant=str(req.get("tenant", "default")))
        digest = sha256_hex(key)
        for known, principal in self._known_hashes.items():
            if hmac.compare_digest(known, digest):       # constant-time compare
                return principal
        return None

    def _log(self, record: dict, raw_prompt: str) -> None:
        if not self.redact_logs:
            record = {**record, "prompt": raw_prompt}
        line = json.dumps(record, sort_keys=True)
        if self.redact_logs:
            line = redact(line, self.secrets.all_values())
        self.log_lines.append(line)

    def _deny(self, root: Span, status: int, reason: str, record: dict, prompt: str) -> dict:
        root.set(**{"http.response.status_code": status, "aisec.decision": reason})
        root.events.append({"name": reason})
        self.tracer.end(root, "ERROR")
        self._log({**record, "status": status, "decision": reason}, prompt)
        return {"status": status, "output": "", "error": reason}

    # ---- main entry point
    def handle(self, req: dict) -> dict:
        prompt = str(req.get("prompt", ""))
        deployment_name = str(req.get("deployment", ""))
        max_tokens = int(req.get("max_tokens", 256))
        headers = req.get("headers") or {}
        root = self.tracer.start("gateway.request")
        root.set(**{"gen_ai.operation.name": "chat", "gen_ai.request.model": deployment_name,
                    "gen_ai.request.max_tokens": max_tokens,
                    # recorded for investigation, never used for identity or limits
                    "client.address": headers.get("X-Forwarded-For", "unknown"),
                    "aisec.prompt.sha256": sha256_hex(prompt)[:16], "aisec.prompt.chars": len(prompt)})
        record: dict[str, Any] = {"trace_id": root.trace_id, "deployment": deployment_name,
                                  "prompt_sha256": sha256_hex(prompt)[:16], "prompt_chars": len(prompt)}

        # L1 authentication
        span = self.tracer.start("gateway.auth", root)
        principal = self._authenticate(req)
        if principal is None:
            key = str(req.get("api_key") or "")
            root.set(**{"aisec.key.fingerprint": fingerprint(key) if key else "none"})
            self.tracer.end(span, "ERROR")
            return self._deny(root, 401, "auth_failed", record, prompt)
        self.tracer.end(span)
        root.set(**{"aisec.principal": principal.id, "aisec.team": principal.team, "aisec.tenant": principal.tenant})
        record.update(principal=principal.id, team=principal.team, tenant=principal.tenant)
        claimed = {k: req[k] for k in ("user", "tenant") if k in req}
        if self.enforce_auth and claimed and (claimed.get("user", principal.id) != principal.id
                                              or claimed.get("tenant", principal.tenant) != principal.tenant):
            root.events.append({"name": "identity_claim_ignored"})   # someone tried to be someone else

        # L3a payload limits (before any expensive work)
        deployment = self.deployments.get(deployment_name)
        if self.enforce_limits:
            if len(prompt) > self.limits.max_prompt_chars:
                return self._deny(root, 413, "payload_too_large", record, prompt)
            if deployment is not None and not 1 <= max_tokens <= deployment.max_output_tokens:
                return self._deny(root, 400, "max_tokens_over_cap", record, prompt)

        # L2 model access control
        span = self.tracer.start("gateway.policy", root)
        if deployment is None:
            self.tracer.end(span, "ERROR")
            return self._deny(root, 404 if not self.enforce_entitlements else 403, "model_denied", record, prompt)
        if self.enforce_entitlements and deployment_name not in self.entitlements.get(principal.team, set()):
            self.tracer.end(span, "ERROR")
            return self._deny(root, 403, "model_denied", record, prompt)
        self.tracer.end(span)

        # L3b rate limits and quota: keyed on the authenticated identity, never on headers
        if self.enforce_limits:
            span = self.tracer.start("gateway.ratelimit", root)
            if not self._p_bucket.allow(principal.id) or not self._t_bucket.allow(principal.tenant):
                self.tracer.end(span, "ERROR")
                return self._deny(root, 429, "rate_limited", record, prompt)
            reserve = rough_tokens(prompt) + max_tokens
            quota = self.limits.team_token_quota.get(principal.team, self.limits.default_team_quota)
            if self.used_tokens[principal.team] + reserve > quota:
                self.tracer.end(span, "ERROR")
                return self._deny(root, 429, "quota_exceeded", record, prompt)
            self.tracer.end(span)

        # L5 input guard (soft): flag, do not trust
        guard_hits = 0
        if self.input_guard and INJECTION_HINTS.search(prompt):
            guard_hits = 1
            root.events.append({"name": "guardrail_hit", "kind": "input.injection_hint"})
        root.set(**{"aisec.guardrail.input_hits": guard_hits})

        # L4 secrets: fetch at call time from the vault; only the provider client sees it
        span = self.tracer.start("gen_ai.chat", root)
        provider_key = self.secrets.get(self.provider_secret_name, accessor="gateway")
        system = SYSTEM_PROMPT
        if not self.keep_secrets_out_of_prompt:          # the VULN 5 mistake, for experiments
            system += f" Internal config: provider_api_key={provider_key}"
        messages = [{"role": "system", "content": system}, {"role": "user", "content": prompt}]
        try:
            output = self.provider.complete(messages, api_key=provider_key)
        except PermissionError:
            self.tracer.end(span, "ERROR")
            return self._deny(root, 502, "upstream_auth_failed", record, prompt)
        in_tok, out_tok = rough_tokens(system + prompt), min(rough_tokens(output), max_tokens)
        span.set(**{"gen_ai.request.model": deployment.model, "gen_ai.usage.input_tokens": in_tok,
                    "gen_ai.usage.output_tokens": out_tok})
        self.tracer.end(span)
        self.used_tokens[principal.team] += in_tok + out_tok
        root.set(**{"gen_ai.usage.input_tokens": in_tok, "gen_ai.usage.output_tokens": out_tok,
                    "gen_ai.response.model": deployment.model})
        record.update(input_tokens=in_tok, output_tokens=out_tok)

        # L6 output guard (hard): no known secret or canary leaves the gateway
        if self.output_guard:
            leaked = [s for s in (*self.secrets.all_values(), *self.canaries) if s and s in output]
            if leaked or any(p.search(output) for p in OUTPUT_SECRET_PATTERNS):
                root.events.append({"name": "output_blocked", "kind": "secret_in_output"})
                return self._deny(root, 502, "output_blocked", record, prompt)

        root.set(**{"http.response.status_code": 200, "aisec.decision": "allowed"})
        self.tracer.end(root)
        self._log({**record, "status": 200, "decision": "allowed", "guardrail_input_hits": guard_hits}, prompt)
        return {"status": 200, "output": output}


# --------------------------------------------------------------------------- a ready-made lab setup

def build_lab_gateway(*, clock: Clock = time.monotonic, llm: LLM | None = None, **flags: Any) -> tuple[SecureModelGateway, dict]:
    """Return a gateway plus the lab's client keys and secrets, all fresh and fake."""
    provider = FakeProvider(llm=llm or get_llm())
    store = SecretStore(clock=clock)
    provider_key = "sk-lab-" + secrets.token_hex(12)
    store.put("provider/api-key", provider_key)
    provider.issue(provider_key)
    keys = {"alice": "gw-" + secrets.token_hex(12), "bob": "gw-" + secrets.token_hex(12),
            "mallory": "gw-" + secrets.token_hex(12)}
    clients = {
        sha256_hex(keys["alice"]): Principal("alice", team="support", tenant="acme"),
        sha256_hex(keys["bob"]): Principal("bob", team="research", tenant="acme"),
        sha256_hex(keys["mallory"]): Principal("mallory", team="support", tenant="globex"),
    }
    deployments = {
        "support-chat": Deployment("support-chat", model="support-llm@3.0.0", max_output_tokens=512),
        "research-large": Deployment("research-large", model="big-llm@2026-06", data_class="restricted",
                                     max_output_tokens=4096),
    }
    entitlements = {"support": {"support-chat"}, "research": {"support-chat", "research-large"}}
    limits = flags.pop("limits", None) or Limits(team_token_quota={"support": 20_000, "research": 50_000})
    gateway = SecureModelGateway(provider=provider, secrets=store, clients=clients, deployments=deployments,
                                 entitlements=entitlements, limits=limits, clock=clock, **flags)
    return gateway, {"client_keys": keys, "provider_key": provider_key, "provider": provider, "store": store}
