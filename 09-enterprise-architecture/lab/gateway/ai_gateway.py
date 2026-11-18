"""Secure AI (LLM) gateway: the single front door for every model call. Offline lab.

One request travels through these layers (flags switch a layer off so you can watch
which attack lands):

    token -> [1 authN: signature, expiry, audience, agent delegation]
          -> [2 request schema + size limit]          (always on)
          -> [3 rate limit per caller]                rate_limit
          -> [4 token budget per tenant]              budget
          -> [5 input DLP: block secrets, mask PII]   dlp
          -> [6 guardrail hook]                       guardrail   (SOFT; fails closed for confidential data)
          -> [7 routing: approved models only]        routing_policy
          -> [8 tenant-scoped response cache]         cache_isolation
          -> [9 provider call with safe failover]     routing_policy
          -> [10 output DLP]                          dlp
          -> answer      ...and [11 audit log] records every step (log_redaction).

HARD layers are deterministic code. The guardrail is a SOFT layer: a classifier that
lowers the odds of an attack and produces signals, but can be fooled or be down.

Everything is simulated: "model endpoints" wrap ``aisec_lab.MockLLM`` and only record
what they receive. This module imports nothing from its sibling lab files.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from aisec_lab import MockLLM

DataClass = Literal["public", "internal", "confidential"]
RANK = {"public": 0, "internal": 1, "confidential": 2}
AUDIENCE = "ai-gateway"


# ===================================================================== 1. identity
class AuthError(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    sub: str
    tenant: str
    kind: Literal["user", "app", "agent"]
    on_behalf_of: str | None = None  # for agents: the user they act for (delegation)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class TokenIssuer:
    """Stand-in for the enterprise IdP / token service: HMAC-signed, short-lived tokens.

    Real systems use asymmetric keys (RS256/ES256) and a maintained JWT library. The
    idea is the same: the gateway trusts only claims it has *verified*, including the
    audience ("is this token meant for me?").
    """

    def __init__(self, signing_key: bytes, clock: Callable[[], float] = time.time) -> None:
        self._key = signing_key
        self._clock = clock

    def issue(self, sub: str, tenant: str, kind: str = "user", aud: str = AUDIENCE,
              ttl: int = 900, on_behalf_of: str | None = None) -> str:
        claims = {"sub": sub, "tenant": tenant, "kind": kind, "aud": aud,
                  "exp": int(self._clock()) + ttl}
        if on_behalf_of:
            claims["act_for"] = on_behalf_of
        payload = _b64(json.dumps(claims, sort_keys=True).encode())
        sig = hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}.{sig}"

    def verify(self, token: str, audience: str = AUDIENCE) -> Principal:
        try:
            payload, sig = token.rsplit(".", 1)
        except (AttributeError, ValueError):
            raise AuthError("malformed token") from None
        good = hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(good, sig):
            raise AuthError("bad signature")
        claims = json.loads(_unb64(payload))
        if claims.get("exp", 0) < self._clock():
            raise AuthError("token expired")
        if claims.get("aud") != audience:
            raise AuthError(f"wrong audience {claims.get('aud')!r}")
        if claims.get("kind") not in ("user", "app", "agent"):
            raise AuthError("unknown principal kind")
        return Principal(claims["sub"], claims["tenant"], claims["kind"], claims.get("act_for"))


# ======================================================================= policy
class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ModelSpec(Strict):
    approved: bool
    max_class: DataClass             # most sensitive data this model may receive
    cost_per_1k_tokens: float = 0.0


class GatewayPolicy(Strict):
    """Routing and limits as data. Validated on load: a bad policy is an error, not a gap."""
    models: dict[str, ModelSpec]
    routes: dict[DataClass, list[str]]  # ordered: primary first, then approved fallbacks
    requests_per_minute: int = 10
    daily_token_budget: int = 3000      # per tenant
    max_prompt_chars: int = 2000

    @model_validator(mode="after")
    def _routes_use_only_approved_models(self) -> "GatewayPolicy":
        for data_class, names in self.routes.items():
            for name in names:
                spec = self.models.get(name)
                if spec is None or not spec.approved:
                    raise ValueError(f"route {data_class}: {name!r} is not an approved model")
                if RANK[spec.max_class] < RANK[data_class]:
                    raise ValueError(f"route {data_class}: {name!r} is only approved up to {spec.max_class}")
        return self

    def allowed(self, name: str, data_class: str) -> bool:
        spec = self.models.get(name)
        return bool(spec and spec.approved and RANK[spec.max_class] >= RANK[data_class])


def default_policy() -> GatewayPolicy:
    return GatewayPolicy.model_validate({
        "models": {
            "corp-llm-private": {"approved": True, "max_class": "confidential", "cost_per_1k_tokens": 0.02},
            "corp-llm-backup": {"approved": True, "max_class": "confidential", "cost_per_1k_tokens": 0.03},
            "vendor-llm-standard": {"approved": True, "max_class": "internal", "cost_per_1k_tokens": 0.01},
            "free-public-llm": {"approved": False, "max_class": "public"},
        },
        "routes": {
            "confidential": ["corp-llm-private", "corp-llm-backup"],
            "internal": ["vendor-llm-standard", "corp-llm-private"],
            "public": ["vendor-llm-standard"],
        },
    })


class Request(Strict):
    prompt: str
    data_class: DataClass = "internal"
    context: str = ""              # tenant data the calling app retrieved (RAG)
    model: str | None = None       # optional hint; must be approved for the data class
    tenant_id: str | None = None   # IGNORED: tenant comes from the token; a mismatch is logged


# =============================================================== model endpoints
class ProviderDown(Exception):
    pass


@dataclass
class ModelEndpoint:
    """A simulated model provider. ``received`` is every prompt that left the gateway."""
    name: str
    available: bool = True
    llm: MockLLM = field(default_factory=MockLLM)
    received: list[str] = field(default_factory=list)

    def complete(self, prompt: str, context: str) -> str:
        if not self.available:
            raise ProviderDown(self.name)
        text = f"<context>{context}</context>\n{prompt}" if context else prompt
        self.received.append(text)
        return f"[{self.name}] " + self.llm.complete([{"role": "user", "content": text}])


def make_endpoints(**down: bool) -> dict[str, ModelEndpoint]:
    """All endpoints that exist in the world, approved or not. ``down`` marks outages."""
    names = ["corp-llm-private", "corp-llm-backup", "vendor-llm-standard", "free-public-llm"]
    return {n: ModelEndpoint(n, available=not down.get(n.replace("-", "_"), False)) for n in names}


# ======================================================================== DLP
SECRET_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|CANARY-[0-9a-f]{10}|SECRET-[0-9a-f]{10}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?i:password\s*[:=]\s*\S+))"
)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")


def redact(text: str) -> str:
    return EMAIL_RE.sub("[EMAIL]", SECRET_RE.sub("[REDACTED]", text))


# ==================================================================== guardrail
class GuardrailUnavailable(Exception):
    pass


ATTACK_RE = re.compile(
    r"(ignore (?:all |any )?(?:previous|prior|above) instructions|system override"
    r"|you are now (?:in )?(?:developer|debug|admin) mode|reveal (?:your|the) system prompt)",
    re.IGNORECASE,
)


def prompt_attack_guardrail(text: str) -> Literal["allow", "block"]:
    """A naive classifier (SOFT layer): catches known phrases, misses paraphrases."""
    return "block" if ATTACK_RE.search(text) else "allow"


# ====================================================================== audit
class AuditLog:
    def __init__(self, redaction: bool = True) -> None:
        self.entries: list[dict] = []
        self.redaction = redaction

    def write(self, cid: str, kind: str, **fields) -> None:
        if self.redaction:
            fields = {k: redact(v) if isinstance(v, str) else v for k, v in fields.items()}
        self.entries.append({"seq": len(self.entries), "cid": cid, "kind": kind, **fields})

    def text(self) -> str:
        return "\n".join(json.dumps(e, sort_keys=True) for e in self.entries)


def fingerprint(token: str) -> str:
    """Log a token's fingerprint, never the token: a log reader must not be able to replay it."""
    return hashlib.sha256(token.encode()).hexdigest()[:12]


# ===================================================================== gateway
@dataclass
class Response:
    status: Literal["ok", "unauthenticated", "bad_request", "rate_limited", "budget_exceeded",
                    "blocked", "denied", "unavailable"]
    answer: str = ""
    model: str | None = None
    cached: bool = False
    correlation_id: str = ""
    reason: str = ""


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / 4)


class SecureGateway:
    def __init__(
        self,
        issuer: TokenIssuer,
        endpoints: dict[str, ModelEndpoint],
        policy: GatewayPolicy | None = None,
        *,
        guardrail: Callable[[str], str] | None = prompt_attack_guardrail,
        clock: Callable[[], float] = time.time,
        rate_limit: bool = True,
        budget: bool = True,
        dlp: bool = True,
        routing_policy: bool = True,
        cache_isolation: bool = True,
        log_redaction: bool = True,
    ) -> None:
        self.issuer, self.endpoints = issuer, endpoints
        self.policy = policy or default_policy()
        self.guardrail, self.clock = guardrail, clock
        self.flags = dict(rate_limit=rate_limit, budget=budget, dlp=dlp, routing_policy=routing_policy,
                          cache_isolation=cache_isolation)
        self.audit = AuditLog(redaction=log_redaction)
        self.cache: dict[str, tuple[str, str]] = {}
        self.calls: dict[tuple[str, str], list[float]] = {}
        self.tokens_used: dict[str, int] = {}
        self.cost: dict[str, float] = {}

    # ---------------------------------------------------------------- helpers
    def _rate_limited(self, p: Principal) -> bool:
        now, key = self.clock(), (p.tenant, p.sub)
        recent = [t for t in self.calls.get(key, []) if now - t < 60]
        self.calls[key] = recent
        if len(recent) >= self.policy.requests_per_minute:
            return True
        recent.append(now)
        return False

    def _cache_key(self, p: Principal, req: Request) -> str:
        if not self.flags["cache_isolation"]:
            parts = [req.prompt]  # the classic bug: same question, same answer, any tenant
        else:
            scope = p.sub if req.data_class == "confidential" else "*"
            parts = [p.tenant, scope, req.data_class, req.model or "", req.context, req.prompt]
        return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()

    def _candidates(self, req: Request) -> list[str]:
        route = list(self.policy.routes.get(req.data_class, []))
        if req.model:
            route = [req.model] + [m for m in route if m != req.model]
        if not self.flags["routing_policy"]:
            route += [m for m in self.endpoints if m not in route]  # "any model that answers"
        return route

    def _deny(self, cid: str, status: str, reason: str) -> Response:
        self.audit.write(cid, "denied", status=status, reason=reason)
        return Response(status, f"[{status}: {reason}]", correlation_id=cid, reason=reason)  # type: ignore[arg-type]

    # ------------------------------------------------------------------ handle
    def handle(self, token: str, body: dict) -> Response:
        cid = secrets.token_hex(6)
        # 1. authentication (always on)
        try:
            p = self.issuer.verify(token)
        except AuthError as exc:
            self.audit.write(cid, "auth_failed", reason=str(exc), token_fp=fingerprint(str(token)))
            return Response("unauthenticated", f"[unauthenticated: {exc}]", correlation_id=cid, reason=str(exc))
        # 2. strict schema and size (always on)
        try:
            req = Request.model_validate(body)
        except ValidationError as exc:
            return self._deny(cid, "bad_request", f"invalid request: {exc.errors()[0]['msg']}")
        entry = dict(sub=p.sub, principal=p.kind, on_behalf_of=p.on_behalf_of, tenant=p.tenant, data_class=req.data_class,
                     prompt=req.prompt, token_fp=fingerprint(token))
        if not self.audit.redaction:
            entry["authorization"] = f"Bearer {token}"  # what a careless debug log does
        self.audit.write(cid, "request", **entry)
        if req.tenant_id and req.tenant_id != p.tenant:
            self.audit.write(cid, "tenant_mismatch_ignored", claimed=req.tenant_id, token_tenant=p.tenant)
        if len(req.prompt) + len(req.context) > self.policy.max_prompt_chars:
            return self._deny(cid, "bad_request", "request too large")
        if p.kind == "agent" and req.data_class == "confidential" and not p.on_behalf_of:
            return self._deny(cid, "denied", "agent token has no delegated user for confidential data")
        # 3. rate limit and 4. budget
        if self.flags["rate_limit"] and self._rate_limited(p):
            return self._deny(cid, "rate_limited", "rate limit (per caller)")
        estimate = estimate_tokens(req.prompt + req.context)
        if self.flags["budget"] and self.tokens_used.get(p.tenant, 0) + estimate > self.policy.daily_token_budget:
            return self._deny(cid, "budget_exceeded", f"tenant {p.tenant} daily token budget")
        # 5. input DLP: secrets never leave the gateway; personal data is masked
        prompt, context = req.prompt, req.context
        if self.flags["dlp"]:
            if SECRET_RE.search(prompt):
                return self._deny(cid, "blocked", "secret in prompt (input DLP)")
            prompt, context = EMAIL_RE.sub("[EMAIL]", prompt), EMAIL_RE.sub("[EMAIL]", context)
        # 6. guardrail hook (soft); if it is down, fail closed for confidential data
        if self.guardrail is not None:
            try:
                verdict = self.guardrail(prompt + "\n" + context)
            except GuardrailUnavailable:
                if req.data_class == "confidential":
                    return self._deny(cid, "unavailable", "guardrail down: fail closed for confidential data")
                self.audit.write(cid, "guardrail_unavailable", action="fail open (non-confidential)")
                verdict = "allow"
            if verdict == "block":
                return self._deny(cid, "blocked", "guardrail: prompt attack")
        # 7. routing: an explicitly requested model must be approved for this data class
        if self.flags["routing_policy"] and req.model and not self.policy.allowed(req.model, req.data_class):
            return self._deny(cid, "denied", f"model {req.model!r} is not approved for {req.data_class} data")
        # 8. cache
        key = self._cache_key(p, req)
        if key in self.cache:
            model, answer = self.cache[key]
            self.audit.write(cid, "response", status="ok", model=model, cached=True)
            return Response("ok", answer, model, cached=True, correlation_id=cid)
        # 9. provider call with safe failover
        for name in self._candidates(req):
            ep = self.endpoints.get(name)
            if ep is None:
                continue
            try:
                raw = ep.complete(prompt, context)
            except ProviderDown:
                self.audit.write(cid, "provider_failed", model=name)
                continue
            # 10. output DLP
            answer = redact(raw) if self.flags["dlp"] else raw
            used = estimate + estimate_tokens(raw)
            self.tokens_used[p.tenant] = self.tokens_used.get(p.tenant, 0) + used
            spec = self.policy.models.get(name)
            self.cost[p.tenant] = self.cost.get(p.tenant, 0.0) + used / 1000 * (spec.cost_per_1k_tokens if spec else 0.0)
            self.cache[key] = (name, answer)
            self.audit.write(cid, "response", status="ok", model=name, tokens=used, answer=answer)
            return Response("ok", answer, name, correlation_id=cid)
        return self._deny(cid, "unavailable", f"no approved model available for {req.data_class} data (fail closed)")
