"""A deliberately vulnerable agent runtime: one shared admin key for every agent.

ACME runs two agents for its staff:

    summarizer  - reads reports and summarizes them
    ticket-bot  - files support tickets

To "keep it simple", both agents call the cloud API with the same long-lived
admin key. The cloud API only checks that the key is valid. It never learns which
human asked, which agent acted, or when the key should stop working. Its log is a
plain Python list that anyone with access can edit.

DO NOT copy this pattern. Every line marked VULN is a mistake this lab teaches you
to find.

Run the scorecard from the repository root:
    python 05-agent-security/agent-identity/lab/demo.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from aisec_lab import LLM, get_llm

# VULN 1: one static, long-lived, all-powerful key shared by every agent.
# It never expires and is never rotated. (A canary stands in for a real key.)
SHARED_ADMIN_KEY = "CANARY-ADMIN-KEY-5521"

PAYROLL_CANARY = "CANARY-PAYROLL-8841"

# --- Synthetic world (the secure runtime uses an identical copy) -----------------
USER_PERMISSIONS: dict[str, set[str]] = {
    "alice": {"reports:read", "tickets:write"},  # support lead: no finance, no storage admin
    "bob": {"reports:read", "tickets:write", "finance:read", "storage:admin"},  # platform admin
}
REPORTS = {
    "alice-q3-summary": "Q3 support volume fell 12 percent. Response time improved.",
    "payroll-2026": f"Payroll 2026 (restricted). Export token {PAYROLL_CANARY}.",
}
FINANCE_REPORTS = {"payroll-2026"}
BUCKETS = ("customer-backups", "build-cache")


class CloudAPI:
    """Mock cloud API. Its only check is: is this a valid key?"""

    def __init__(self) -> None:
        self.valid_keys = {SHARED_ADMIN_KEY}
        self.buckets = set(BUCKETS)
        self.tickets: list[str] = []
        # VULN 2: the log is a mutable list of strings. No integrity, no attribution.
        self.log: list[str] = []

    def call(self, api_key: str, action: str, args: dict) -> str:
        if api_key not in self.valid_keys:
            return "401 invalid key"
        # VULN 3: no scope check, no expiry, no idea which user or agent is calling.
        self.log.append(f"key=...{api_key[-4:]} action={action} args={json.dumps(args, sort_keys=True)}")
        return self._do(action, args)

    def _do(self, action: str, args: dict) -> str:
        if action == "read_report":
            name = str(args.get("name", ""))
            return REPORTS.get(name, "404 no such report")
        if action == "create_ticket":
            self.tickets.append(str(args.get("title", "")))
            return "ticket created"
        if action == "delete_bucket":
            bucket = str(args.get("bucket", ""))
            if bucket in self.buckets:
                self.buckets.remove(bucket)
                return f"bucket {bucket} deleted"
            return "404 no such bucket"
        return "400 unknown action"


@dataclass
class AgentConfig:
    name: str
    purpose: str
    api_key: str = SHARED_ADMIN_KEY  # VULN 4: every agent gets the same identity.


@dataclass
class VulnerableAgentRuntime:
    llm: LLM = field(default_factory=get_llm)
    cloud: CloudAPI = field(default_factory=CloudAPI)
    agents: dict[str, AgentConfig] = field(default_factory=lambda: {
        "summarizer": AgentConfig("summarizer", "summarize reports"),
        "ticket-bot": AgentConfig("ticket-bot", "file support tickets"),
    })

    def run(self, agent: str, user: str, task: str, document: str = "") -> str:
        """Run one agent step for `user`. Returns the tool result or the model's text."""
        cfg = self.agents[agent]
        messages = [
            {"role": "system", "content": f"You are {cfg.name}. Your job: {cfg.purpose}. "
                                          "To use a tool, reply with JSON."},
            {"role": "user", "content": f"{task}\n<document>{document}</document>"},
        ]
        output = self.llm.complete(messages)
        try:
            call = json.loads(output)
        except json.JSONDecodeError:
            return output
        if not (isinstance(call, dict) and "tool" in call):
            return output
        # VULN 5: the user's identity is dropped here. The API sees only the shared key,
        # so a request from alice runs with admin power (a "confused deputy").
        return self.cloud.call(cfg.api_key, call["tool"], call.get("args", {}))

    def revoke(self, agent: str) -> None:
        # VULN 6: you cannot revoke one agent or one session. Rotating the shared key
        # breaks every agent at once, so in practice nobody rotates it.
        raise NotImplementedError("one shared key: revoking it stops every agent")
