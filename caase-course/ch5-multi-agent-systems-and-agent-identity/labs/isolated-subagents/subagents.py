"""Isolated subagents: separate context, tools and credentials per subagent.

Offline twin of "delegating subtasks to isolated subagents" (as a harness such as
Hermes Agent does). The orchestrator spawns subagents that each get:
  - a fresh context (no copy of the parent's or siblings' messages),
  - an explicit tool allowlist (least agency),
  - their own short-lived credential, valid only for named resources,
and returns only a bounded, structured summary to the parent.

``SharedPool`` is the vulnerable design: one shared context, one shared tool set
and one shared credential. Canaries are FAKE.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Callable

Tool = Callable[..., str]


class Denied(Exception):
    pass


@dataclass
class Vault:
    """Resource server: a credential works only for its listed resources."""

    data: dict[str, str]
    creds: dict[str, set[str]] = field(default_factory=dict)  # credential -> resources
    revoked: set[str] = field(default_factory=set)

    def issue(self, resources: set[str]) -> str:
        cred = "cred-" + secrets.token_hex(6)
        self.creds[cred] = set(resources)
        return cred

    def revoke(self, cred: str) -> None:
        self.revoked.add(cred)

    def read(self, cred: str, resource: str) -> str:
        if cred in self.revoked or cred not in self.creds:
            raise Denied("credential invalid or revoked")
        if resource not in self.creds[cred]:
            raise Denied(f"credential not valid for {resource}")
        return self.data[resource]


@dataclass
class SubAgent:
    name: str
    tools: dict[str, Tool]
    credential: str
    vault: Vault
    context: list[str] = field(default_factory=list)  # private to this subagent
    alive: bool = True

    def remember(self, text: str) -> None:
        self.context.append(text)

    def call(self, tool: str, *args) -> str:
        if not self.alive:
            raise Denied("subagent terminated")
        if tool not in self.tools:
            raise Denied(f"{self.name} has no tool {tool}")
        return self.tools[tool](self, *args)

    def finish(self, max_chars: int = 200) -> dict:
        """Only this bounded summary goes back to the parent. Never the raw context."""
        summary = (self.context[-1] if self.context else "")[:max_chars]
        return {"agent": self.name, "summary": summary, "untrusted": True}

    def terminate(self) -> None:
        self.alive = False
        self.context.clear()
        self.vault.revoke(self.credential)


# Example tools -------------------------------------------------------------
def tool_read_resource(agent: SubAgent, resource: str) -> str:
    return agent.vault.read(agent.credential, resource)


def tool_note(agent: SubAgent, text: str) -> str:
    agent.remember(text)
    return "noted"


STANDARD_TOOLS = {"read_resource": tool_read_resource, "note": tool_note}


class Orchestrator:
    def __init__(self, vault: Vault) -> None:
        self.vault = vault
        self.parent_context: list[str] = []
        self.children: dict[str, SubAgent] = {}

    def spawn(self, name: str, tools: list[str], resources: set[str]) -> SubAgent:
        unknown = [t for t in tools if t not in STANDARD_TOOLS]
        if unknown:
            raise Denied(f"unknown tools {unknown}")
        agent = SubAgent(
            name=name,
            tools={t: STANDARD_TOOLS[t] for t in tools},
            credential=self.vault.issue(resources),
            vault=self.vault,
            context=[],  # fresh, NOT a copy of parent_context
        )
        self.children[name] = agent
        return agent

    def collect(self, agent: SubAgent) -> dict:
        result = agent.finish()
        self.parent_context.append(f"[subagent {agent.name} said, UNTRUSTED]: {result['summary']}")
        return result


# Vulnerable design ----------------------------------------------------------
class SharedPool:
    """All 'subagents' share one context, one tool set and one credential."""

    def __init__(self, vault: Vault, resources: set[str]) -> None:
        self.vault = vault
        self.context: list[str] = []
        self.credential = vault.issue(resources)  # union of everything

    def run(self, who: str, resource: str) -> str:
        data = self.vault.read(self.credential, resource)
        self.context.append(f"{who} read {resource}: {data}")
        return data
