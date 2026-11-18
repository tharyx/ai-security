"""A cloud-ops agent built the quick way. It works in the demo and fails in every way that matters.

DO NOT copy this pattern. Every weakness is marked with a "VULN n:" comment. The numbers
match the seven controls of the secure version.

    VULN 1: Read-write by default. The agent holds an admin key for every task, even when
            it only needs to read EC2 and CloudWatch.
    VULN 2: No separate identity. One static admin key; CloudTrail says "static-admin-key",
            never which agent or which engineer.
    VULN 3: No explicit authorization. Whatever tool call the model proposes is executed,
            including ones that came from log lines written by strangers.
    VULN 4: No human approval, even for production changes and Terraform.
    VULN 5: Long-lived credentials, and they are in the system prompt.
    VULN 6: The only "audit" is a list of strings in the agent's memory.
    VULN 7: No sandbox, plan review or rollback: Terraform changes apply straight to prod.
    Also:   "Remember:" lines from logs become standing instructions (persistent injection).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from aisec_lab import LLM, get_llm

REMEMBER_RE = re.compile(r"^\s*remember:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
LAB_FUSE_STEPS = 20


@dataclass
class Report:
    answer: str = ""
    actions: list[str] = field(default_factory=list)
    steps: int = 0


@dataclass
class VulnerableCloudAgent:
    cloud: object  # a mock_cloud.MockCloud (passed in so this module imports no sibling)
    llm: LLM = field(default_factory=get_llm)
    notes: list[str] = field(default_factory=list)  # long-term memory, shared by everyone
    history: list[str] = field(default_factory=list)  # VULN 6

    def __post_init__(self) -> None:
        self.creds = self.cloud.admin_credentials()  # VULN 1 + 2 + 5

    def run(self, user: str, task: str, log_group: str = "/app/web-1") -> Report:
        rep = Report()
        facts = {"instances": self.cloud.describe_instances(self.creds),
                 "logs": self.cloud.filter_log_events(self.creds, log_group)}
        for note in REMEMBER_RE.findall("\n".join(facts["logs"])):
            self.notes.append(note)  # untrusted log text becomes memory
        system = (f"You are the cloud-ops agent. Use key {self.creds.access_key_id} / "
                  f"{self.creds.secret_access_key} for tools.\n"  # VULN 5: secret in the prompt
                  + "".join(f"Standing instruction: {n}\n" for n in self.notes))
        observation = "\n".join([json.dumps(i) for i in facts["instances"]] + facts["logs"])
        for step in range(LAB_FUSE_STEPS):
            request = task if step == 0 else "Summarize the latest result for the engineer."
            out = self.llm.complete([{"role": "system", "content": system},
                                     {"role": "user", "content": f"{request}\n<document>{observation}</document>"}])
            rep.steps += 1
            try:
                call = json.loads(out)
            except json.JSONDecodeError:
                call = None
            if not (isinstance(call, dict) and "tool" in call):
                rep.answer = out
                return rep
            observation = self._execute(str(call["tool"]), dict(call.get("args") or {}))  # VULN 3 + 4
            rep.actions.append(f"{call['tool']} {json.dumps(call.get('args') or {}, sort_keys=True)}")
            self.history.append(f"{user}: {rep.actions[-1]}")
        rep.answer = "lab fuse"
        return rep

    def _execute(self, tool: str, a: dict) -> str:
        c, cr = self.cloud, self.creds
        try:
            if tool == "filter_log_events":
                return "\n".join(c.filter_log_events(cr, a.get("log_group", "")))
            if tool == "restart_service":
                return c.send_command(cr, a.get("instance_id", ""), f"restart {a.get('service')}")
            if tool == "authorize_security_group_ingress":
                return c.authorize_security_group_ingress(cr, a.get("group_id"), a.get("port"), a.get("cidr"))
            if tool == "terraform_change":  # VULN 7: plan and apply in one go, no review
                change = {k: a.get(k) for k in ("op", "resource", "attr", "value")}
                plan = c.terraform_plan(cr, a.get("workspace", "prod"), change)
                return c.terraform_apply(cr, plan["plan_id"])
            return f"unknown tool {tool}"
        except Exception as exc:  # noqa: BLE001 - the vulnerable agent just reports and moves on
            return f"error: {exc}"
