"""The "gateway" the hackathon team built: a thin proxy in front of the models.

It works, it is fast, and every team uses it. It is also the reason the platform
cannot answer "who called which model with what data". Every "VULN n" comment is a gap
that the secure gateway (ai_gateway.py) closes. Offline and simulated: the endpoints
only record what they receive.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass

SHARED_API_KEY = "team-shared-key-0001"  # VULN 1: one static key for every app, user and agent


@dataclass
class Response:
    status: str
    answer: str = ""
    model: str | None = None
    cached: bool = False
    correlation_id: str = ""
    reason: str = ""


class VulnerableGateway:
    def __init__(self, endpoints: dict, default_model: str = "vendor-llm-standard") -> None:
        self.endpoints = endpoints
        self.default_model = default_model
        self.cache: dict[str, tuple[str, str]] = {}
        self.debug_log: list[str] = []
        self.served = 0

    def handle(self, token: str, body: dict) -> Response:
        cid = secrets.token_hex(6)
        # VULN 8: the full request, including the bearer credential, goes to the debug log
        self.debug_log.append(json.dumps({"cid": cid, "authorization": f"Bearer {token}", "body": body}))
        if token != SHARED_API_KEY:
            return Response("unauthenticated", "[unauthenticated]", correlation_id=cid)
        # VULN 2: tenant and user come from the request body, so anyone can claim any tenant
        tenant = body.get("tenant_id", "default")
        prompt, context = body.get("prompt", ""), body.get("context", "")
        # VULN 3: no rate limit, no token budget, no size limit
        # VULN 5: answer cache keyed only by the question text, shared by every tenant
        key = hashlib.sha256(prompt.encode()).hexdigest()
        if key in self.cache:
            model, answer = self.cache[key]
            return Response("ok", answer, model, cached=True, correlation_id=cid)
        # VULN 4: the model name from the request is used as-is; no approved list, no data class
        wanted = body.get("model") or self.default_model
        # VULN 6: if the model is down, fail over to ANY endpoint that answers
        order = [wanted] + [m for m in self.endpoints if m != wanted]
        for name in order:
            ep = self.endpoints.get(name)
            if ep is None:
                continue
            try:
                # VULN 7: no DLP: secrets and personal data go to the provider and come back
                answer = ep.complete(prompt, context)
            except Exception:  # noqa: BLE001 - any error: just try the next one
                continue
            self.cache[key] = (name, answer)
            self.served += 1
            self.debug_log.append(json.dumps({"cid": cid, "tenant": tenant, "model": name, "answer": answer}))
            return Response("ok", answer, name, correlation_id=cid)
        # VULN 9: no guardrail at all, and nothing records which caller or tenant was refused
        return Response("unavailable", "[all models down]", correlation_id=cid)
