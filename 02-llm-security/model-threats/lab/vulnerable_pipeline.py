"""ACME's model pipeline as first shipped. Every part trusts something it should not.

Five parts, one per model-level threat:

* ``VulnerableTrainingPipeline``  trains on whatever data arrives (poisoning, LLM05:2026).
* ``VulnerableModelAPI``          serves full probabilities with no limits (extraction,
                                  LLM06:2026 Unbounded Consumption / model theft).
* ``VulnerableHelpdesk``          shows unchecked answers from unvetted sources (misinformation,
                                  LLM07:2026).
* ``VulnerableModelLoader``       loads "latest" from a hub with no checks (supply chain, LLM04:2026).
* ``VulnerableCodeFlow``          merges AI-generated code unreviewed (LLM10:2026, incl. AI code).

Dependencies (model classes, data, the hub) are passed in, so tests can inject them.
Everything is simulated and harmless: nothing is unpickled, executed or sent anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


# ---------- Part A: training data poisoning ------------------------------------------

@dataclass
class VulnerableTrainingPipeline:
    model_factory: Callable[[], Any]
    log: list[str] = field(default_factory=list)

    def train(self, batches: list[dict]) -> Any:
        samples = []
        for batch in batches:
            # VULN 1: any source is accepted. Nobody asks where a batch came from.
            # VULN 2: no integrity check. A batch changed after review is still used.
            samples.extend(batch["samples"])
            self.log.append(f"accepted {batch['batch_id']} from {batch['source']}")
        # VULN 3: no data validation (rare trigger words, labels that contradict the text).
        model = self.model_factory().train(samples)
        # VULN 4: no behavior test before release. Clean accuracy is all anyone checks.
        return model


# ---------- Part B: model extraction ----------------------------------------------------

@dataclass
class VulnerableModelAPI:
    model: Any
    queries: dict[str, int] = field(default_factory=dict)

    def query(self, api_key: str, text: str) -> dict:
        # VULN 5: no query budget and no rate limit per key: mass querying is free.
        # VULN 6: no monitoring of query patterns (single-word probes, sweeps).
        self.queries[api_key] = self.queries.get(api_key, 0) + 1
        proba = self.model.predict_proba(text)
        # VULN 7: full probabilities with 4 decimals: each answer leaks the model's weights.
        return {"label": self.model.predict(text),
                "scores": {k: round(v, 4) for k, v in proba.items()}}


# ---------- Part C: misinformation and overreliance -------------------------------------

@dataclass
class VulnerableHelpdesk:
    llm: Any
    knowledge_base: dict[str, dict]

    def answer(self, question: str) -> str:
        # VULN 8: every document goes into the context, approved or not (a scraped forum
        # post counts as much as the official policy).
        context = "\n".join(f"[doc:{d}] {doc['text']}" for d, doc in self.knowledge_base.items())
        # VULN 9: the draft is shown as-is: citations, numbers and claims are never checked,
        # and "I don't know" is never an option.
        # VULN 10: high-stakes questions (medical, legal, money) get the same treatment.
        return self.llm.complete([
            {"role": "system", "content": "You are ACME Travel's helpful assistant."},
            {"role": "user", "content": f"<context>\n{context}\n</context>"},
            {"role": "user", "content": question},
        ])


# ---------- Part D: supply chain ---------------------------------------------------------

@dataclass
class LoadResult:
    name: str
    version: str
    loaded: bool
    code_executed_on_load: bool = False   # simulated impact of an unsafe format
    reason: str = ""


@dataclass
class VulnerableModelLoader:
    hub: dict[tuple[str, str], dict]

    def load(self, name: str, version: str = "latest") -> LoadResult:
        # VULN 11: "latest" is resolved at load time: whatever was published last wins.
        if version == "latest":
            versions = sorted(v for (n, v) in self.hub if n == name)
            if not versions:
                return LoadResult(name, version, False, reason="not found")
            version = versions[-1]
        artifact = self.hub.get((name, version))
        if artifact is None:
            return LoadResult(name, version, False, reason="not found")
        # VULN 12: any publisher. VULN 13: no digest check against an approved inventory.
        # VULN 14: unsafe formats are loaded. A real pickle can run code during loading;
        # here we only *record* that it would have.
        unsafe = artifact["format"] == "pickle" or artifact["data"][:1] == b"\x80"
        return LoadResult(name, version, True, code_executed_on_load=unsafe)


# ---------- Part E: AI-generated code ------------------------------------------------------

@dataclass
class VulnerableCodeFlow:
    merged: list[str] = field(default_factory=list)

    def submit(self, code: str) -> bool:
        # VULN 15: AI-generated code is merged because "the assistant wrote it and the
        # tests pass". No check for dangerous calls or invented (hallucinated) packages.
        self.merged.append(code)
        return True
