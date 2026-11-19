"""A policy router between a "local" and a "cloud" mock model. Offline; latency and cost are SIMULATED.

The router is the piece a gateway such as LiteLLM, or a routing service such as OpenRouter, plays
for you. The security lesson: the router must decide by POLICY (data classification, size), must not
trust the caller's own label, and must prove that confidential data never reached the cloud side.

    request -> DLP scan (do not trust the label) -> policy -> local | cloud | refuse -> audit log
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

LEVELS = ["public", "internal", "confidential", "restricted"]

# Fake, obviously-marked patterns the DLP scan treats as confidential (all values in tests are FAKE).
DLP_PATTERNS = {
    "fake-api-key": re.compile(r"\bFAKE-KEY-[A-Za-z0-9]{6,}\b"),
    "email-address": re.compile(r"\b[\w.+-]+@[\w-]+\.(?:example|test)\b"),
    "customer-id": re.compile(r"\bCUST-\d{5,}\b"),
    "canary": re.compile(r"\bCANARY-[A-Za-z0-9-]{4,}\b"),
}


@dataclass
class Request:
    prompt: str
    classification: str = "public"  # caller's claim; not trusted
    complexity: str = "low"  # low | high (a stand-in for "needs a bigger model")

    @property
    def est_tokens(self) -> int:
        return max(1, len(self.prompt) // 4)


@dataclass
class Response:
    text: str
    served_model: str
    latency_ms: int
    cost_usd: float
    where: str


class LocalModel:
    """Small, private, free, slow-ish, and limited: short context, short answers."""

    name = "local-small"
    max_ctx_tokens = 2000
    quality = 1

    def __init__(self):
        self.calls: list[Request] = []

    def complete(self, req: Request) -> Response:
        self.calls.append(req)
        text = "[local-small] " + " ".join(req.prompt.split())[:60]
        return Response(text, self.name, 400 + req.est_tokens, 0.0, "local")


class CloudModel:
    """Large, shared, billed, logged by the provider. ``substitute`` simulates a router that serves another model."""

    name = "cloud-large"
    max_ctx_tokens = 128_000
    quality = 3
    price_per_1k_tokens = 0.01

    def __init__(self, substitute: str | None = None):
        self.substitute = substitute
        self.calls: list[Request] = []
        self.provider_log: list[str] = []  # what the provider can see and keep (illustrative)

    def complete(self, req: Request) -> Response:
        self.calls.append(req)
        self.provider_log.append(req.prompt)
        text = "[cloud-large] detailed answer about: " + " ".join(req.prompt.split())[:60]
        cost = round((req.est_tokens + 200) / 1000 * self.price_per_1k_tokens, 6)
        return Response(text, self.substitute or self.name, 900 + req.est_tokens // 10, cost, "cloud")


def scan(prompt: str) -> list[str]:
    return [name for name, rx in DLP_PATTERNS.items() if rx.search(prompt)]


def effective_classification(req: Request) -> tuple[str, list[str]]:
    """The stricter of the caller's label and what the scan finds. Never lower than the label."""
    hits = scan(req.prompt)
    label = req.classification if req.classification in LEVELS else "restricted"  # unknown label: strictest
    if hits and LEVELS.index(label) < LEVELS.index("confidential"):
        label = "confidential"
    return label, hits


@dataclass
class Router:
    local: LocalModel = field(default_factory=LocalModel)
    cloud: CloudModel = field(default_factory=CloudModel)
    audit: list[dict] = field(default_factory=list)

    def route(self, req: Request) -> dict:
        cls, hits = effective_classification(req)
        confidential = LEVELS.index(cls) >= LEVELS.index("confidential")
        too_big = req.est_tokens > self.local.max_ctx_tokens
        wants_big = req.complexity == "high" or too_big
        if confidential and wants_big:
            decision, why = "refuse", "needs a bigger model but data is confidential: use an approved private deployment"
        elif confidential:
            decision, why = "local", "confidential data stays local"
        elif wants_big:
            decision, why = "cloud", "task exceeds local capacity and data is not confidential"
        else:
            decision, why = "local", "small task, run locally"
        out = {"decision": decision, "reason": why, "classification": cls, "dlp_hits": hits, "response": None,
               "substitution_detected": False}
        if decision == "local":
            out["response"] = self.local.complete(req)
        elif decision == "cloud":
            resp = self.cloud.complete(req)
            out["response"] = resp
            out["substitution_detected"] = resp.served_model != self.cloud.name
        self.audit.append({"decision": decision, "classification": cls, "dlp_hits": hits,
                           "tokens": req.est_tokens, "substitution": out["substitution_detected"]})
        return out

    def compare(self, req: Request) -> dict:
        """Run the same request on both models (bypassing policy) to compare. Use only with public test data."""
        a, b = self.local.complete(req), self.cloud.complete(req)
        return {"local": a, "cloud": b, "latency_ratio": round(b.latency_ms / a.latency_ms, 2),
                "extra_cost_usd": round(b.cost_usd - a.cost_usd, 6)}
