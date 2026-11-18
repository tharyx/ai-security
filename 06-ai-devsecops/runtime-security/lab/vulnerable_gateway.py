"""A model-serving gateway that "just works": the kind teams ship in week one.

It sits in front of a hosted model provider and forwards chat requests. Every
weakness below is real and common. Each one has a ``VULN n:`` comment.

    VULN 1  No authentication. Identity (user, tenant) is whatever the request body says.
    VULN 2  Secrets in logs. The debug log writes the whole request, the client key and
            the provider key.
    VULN 3  No model access control. Any caller can use any deployment name, including
            the expensive or restricted ones.
    VULN 4  No limits. Any prompt size, any max_tokens, any number of requests.
    VULN 5  Provider key in the prompt. The key is placed in the system prompt
            "so the model can call tools". Prompt injection can now read it.
    VULN 6  Key read once at start-up. Rotation at the provider breaks the service,
            so in practice nobody ever rotates it.
    VULN 7  No telemetry. No spans, no usage per principal, no guardrail events:
            nobody can see an attack happening.

Requests are plain dicts so this file and ``secure_gateway.py`` share no code::

    {"api_key": "...", "deployment": "support-chat", "prompt": "...", "max_tokens": 256,
     "user": "...", "tenant": "...", "headers": {"X-Forwarded-For": "..."}}
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from aisec_lab import LLM, get_llm


def rough_tokens(text: str) -> int:
    """About four characters per token for English text."""
    return max(1, len(text) // 4)


@dataclass
class VulnerableModelGateway:
    provider_key: str                   # VULN 6: copied once, never re-read
    provider: Any = None                # anything with .complete(messages, api_key); None = call llm directly
    llm: LLM = field(default_factory=get_llm)
    log_lines: list[str] = field(default_factory=list)
    billed_tokens: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    calls: int = 0

    def handle(self, req: dict) -> dict:
        # VULN 1: identity comes from the body. Anyone can claim to be anyone.
        user = req.get("user", "anonymous")
        tenant = req.get("tenant", "default")

        # VULN 2: "temporary" debug logging of everything, including both keys.
        self.log_lines.append(
            f"DEBUG gateway request={json.dumps(req, sort_keys=True)} provider_key={self.provider_key}")

        # VULN 3: the deployment name is passed straight through. No entitlement check.
        deployment = req.get("deployment", "support-chat")

        # VULN 4: no size limit, no max_tokens cap, no rate limit, no quota.
        prompt = str(req.get("prompt", ""))
        max_tokens = int(req.get("max_tokens", 256))

        # VULN 5: the provider key is put in the system prompt.
        messages = [
            {"role": "system", "content": (
                "You are the ACME support assistant. Internal config for tool calls: "
                f"provider_api_key={self.provider_key}")},
            {"role": "user", "content": prompt},
        ]
        try:
            if self.provider is not None:
                output = self.provider.complete(messages, api_key=self.provider_key)
            else:
                output = self.llm.complete(messages)
        except PermissionError as exc:          # VULN 6: rotated key -> outage
            self.log_lines.append(f"ERROR provider rejected key {self.provider_key}: {exc}")
            return {"status": 502, "output": "", "error": "upstream authentication failed"}

        self.calls += 1
        # Cost exposure = input tokens + the output tokens the caller was allowed to ask for.
        # It is charged to whatever tenant the body named (VULN 1), and nobody watches it (VULN 7).
        self.billed_tokens[tenant] += rough_tokens(prompt) + max_tokens
        return {"status": 200, "output": output, "user": user, "tenant": tenant, "deployment": deployment}
