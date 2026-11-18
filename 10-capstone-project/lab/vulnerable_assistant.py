"""A deliberately vulnerable AI operations assistant (the "hackathon build").

It has the same features as ``ops_assistant.py``: identity, RAG, an LLM, tools and an
agent loop. Every line marked VULN is one of the mistakes the capstone must remove.
All tools are simulated: nothing touches a real system or the network.

DO NOT copy this pattern.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field

from aisec_lab import LLM, get_llm

STOPWORDS = {"what", "the", "are", "for", "and", "with", "how", "does", "any", "our", "your",
             "this", "that", "from", "into", "about", "please", "there", "where", "why", "which",
             "show", "tell", "give", "have", "see", "is", "it", "do", "we", "a", "an", "to", "of",
             "in", "on", "my", "be", "can", "you", "i"}
TOKEN_RE = re.compile(r"[a-z0-9]+")
DIRECTIVE_RE = re.compile(r"CALL_TOOL\s+\S+\s*(\{.*?\})?", re.DOTALL)


def terms(text: str) -> set[str]:
    return {t for t in TOKEN_RE.findall(text.lower()) if t not in STOPWORDS and len(t) > 2}


@dataclass
class Result:
    status: str
    answer: str
    retrieved: list[str] = field(default_factory=list)
    executed: list[dict] = field(default_factory=list)
    steps: int = 0


class VulnerableOpsAssistant:
    MAX_ITERATIONS = 25  # VULN 1: a "safety net" that is really a runaway budget

    def __init__(self, documents: list[dict], services: dict[str, str],
                 metrics: dict[str, str] | None = None, llm: LLM | None = None) -> None:
        self.documents, self.services, self.metrics = documents, services, metrics or {}
        self.llm = llm or get_llm()
        self.debug_log: list[str] = []      # VULN 2: raw prompts logged, no redaction
        self.change_requests: list[dict] = []
        self.outbound: list[dict] = []      # where http_post "sent" data
        # VULN 3: debug tools left enabled; no registry, no schemas, no roles
        self.tools = {
            "get_service_metrics": lambda service="", **_: f"{service}: {self.metrics.get(service, 'unknown')}",
            "create_change_request": self._create_change,
            "run_shell": lambda cmd="", **_: f"simulated shell output for: {cmd}",
            "http_post": self._http_post,
        }

    def _create_change(self, **args: object) -> str:
        self.change_requests.append(dict(args))
        return f"CR-{1000 + len(self.change_requests)} created"

    def _http_post(self, url: str = "", body: str = "", **_: object) -> str:
        self.outbound.append({"url": url, "body": body})
        return f"posted to {url}"

    @staticmethod
    def _claims(token: str) -> dict:
        # VULN 4: decodes the token but never checks the signature or the expiry
        payload = token.split(".")[0]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))

    def _search(self, query: str, tenant: str) -> list[dict]:
        q = terms(DIRECTIVE_RE.sub(" ", query))
        # VULN 5: filters on a tenant the client can choose, and ignores document groups
        pool = [d for d in self.documents if d["tenant"] == tenant]
        scored = [(len(q & terms(d["title"] + " " + d["text"])), d) for d in pool]
        return [d for s, d in sorted(scored, key=lambda s: -s[0]) if s >= 2][:2]

    def handle(self, token: str, question: str, *, tenant_id: str | None = None) -> Result:
        # VULN 9: no rate limit, no quota, no kill switch, no audit trail
        claims = self._claims(token)
        tenant = tenant_id or claims["tenant"]  # VULN 6: request body overrides the token
        self.debug_log.append(f"{claims['sub']} asked: {question}")
        docs = self._search(question, tenant)
        # VULN 7: untrusted wiki text pasted into the prompt with no marking
        context = "\n".join(f"{d['title']}. {d['text']}" for d in docs)
        content = f"<context>{context}</context>\n\nQuestion: {question}" if docs else f"Question: {question}"
        messages = [{"role": "system", "content": "You are OpsAssistant. Be helpful."},
                    {"role": "user", "content": content}]
        executed: list[dict] = []
        for step in range(1, self.MAX_ITERATIONS + 1):
            output = self.llm.complete(messages)
            try:
                call = json.loads(output)
            except json.JSONDecodeError:
                return Result("ok", output, [d["id"] for d in docs], executed, step)
            # VULN 8: whatever the model asks for runs - any tool, any args, any tenant,
            # no approval for writes
            tool = self.tools.get(call.get("tool"))
            if tool is None:
                return Result("ok", f"unknown tool {call.get('tool')}", [d["id"] for d in docs], executed, step)
            result = tool(**call.get("args", {}))
            executed.append({"tool": call["tool"], "args": call.get("args", {})})
            messages += [{"role": "assistant", "content": output},
                         {"role": "user", "content": f"TOOL_RESULT {call['tool']}: {result}"}]
        return Result("ok", f"Tool result: {result}", [d["id"] for d in docs], executed, self.MAX_ITERATIONS)
