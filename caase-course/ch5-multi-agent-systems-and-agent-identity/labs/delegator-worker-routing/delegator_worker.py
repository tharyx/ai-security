"""Delegator/worker pair with a LOCAL and a CLOUD-ROUTED mock model.

Idea: an orchestrator (delegator) splits a task into subtasks. Each subtask is
classified by data sensitivity and routed to a model: restricted data never
leaves the machine (local model), public data may use the stronger cloud model.
Both models are offline mocks. The "cloud" keeps a log of everything it was sent,
which is what a real provider would also see. Tests assert on that log (impact).

All secrets below are FAKE canaries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aisec_lab import MockLLM

PUBLIC, INTERNAL, RESTRICTED = "public", "internal", "restricted"

RESTRICTED_RE = re.compile(
    r"(FAKE-SSN-\d+|FAKE-KEY-[A-Za-z0-9]+|CONFIDENTIAL|patient record|\b\d{3}-\d{2}-\d{4}\b)", re.I
)
INTERNAL_RE = re.compile(r"(internal only|acme-corp|employee|roadmap)", re.I)


def classify(text: str) -> str:
    """Deterministic data classification. The highest class wins."""
    if RESTRICTED_RE.search(text):
        return RESTRICTED
    if INTERNAL_RE.search(text):
        return INTERNAL
    return PUBLIC


def redact(text: str) -> str:
    """Remove restricted markers and internal names (used before a cloud call for INTERNAL data)."""
    text = RESTRICTED_RE.sub("[REDACTED]", text)
    return INTERNAL_RE.sub("[INTERNAL]", text)


@dataclass
class Model:
    """A mock model with a location. ``seen`` is what its operator could read."""

    name: str
    location: str  # "local" | "cloud"
    available: bool = True
    seen: list[str] = field(default_factory=list)
    _llm: MockLLM = field(default_factory=MockLLM)

    def complete(self, prompt: str) -> str:
        if not self.available:
            raise ConnectionError(f"{self.name} unavailable")
        self.seen.append(prompt)
        return self._llm.complete([{"role": "user", "content": prompt}])


class RoutingError(Exception):
    pass


@dataclass
class Router:
    local: Model
    cloud: Model
    allow_cloud_for_internal: bool = False  # policy switch; default is conservative

    def route(self, text: str) -> tuple[Model, str, str]:
        """Return (model, prompt_to_send, classification). Fails closed."""
        cls = classify(text)
        if cls == RESTRICTED:
            if not self.local.available:
                raise RoutingError("restricted data and local model down: refuse (fail closed)")
            return self.local, text, cls
        if cls == INTERNAL:
            if self.allow_cloud_for_internal:
                return self.cloud, redact(text), cls
            if self.local.available:
                return self.local, text, cls
            raise RoutingError("internal data and local model down: refuse")
        return self.cloud, text, cls  # public: cloud (stronger); worker falls back to local


@dataclass
class NaiveRouter:
    """Vulnerable: sends everything to the cloud because it is 'better'."""

    local: Model
    cloud: Model

    def route(self, text: str) -> tuple[Model, str, str]:
        return self.cloud, text, "unclassified"


@dataclass
class Result:
    subtask: str
    classification: str
    model: str
    location: str
    output: str


class Worker:
    def __init__(self, router) -> None:
        self.router = router

    def run(self, subtask: str) -> Result:
        model, prompt, cls = self.router.route(subtask)
        try:
            out = model.complete(prompt)
        except ConnectionError:
            # Public work may fall back to local; restricted never reaches the cloud anyway.
            if cls == PUBLIC and model.location == "cloud" and self.router.local.available:
                model = self.router.local
                out = model.complete(prompt)
            else:
                raise
        return Result(subtask, cls, model.name, model.location, out)


class Delegator:
    """Splits a task on lines starting with '- ' and hands each to the worker."""

    def __init__(self, worker: Worker) -> None:
        self.worker = worker

    def split(self, task: str) -> list[str]:
        return [ln[2:].strip() for ln in task.splitlines() if ln.startswith("- ")]

    def run(self, task: str) -> list[Result]:
        return [self.worker.run(s) for s in self.split(task)]


def make_pair(*, naive: bool = False, **router_kw):
    local = Model("local-mock-1b", "local")
    cloud = Model("cloud-mock-large", "cloud")
    router = NaiveRouter(local, cloud) if naive else Router(local, cloud, **router_kw)
    return Delegator(Worker(router)), local, cloud
