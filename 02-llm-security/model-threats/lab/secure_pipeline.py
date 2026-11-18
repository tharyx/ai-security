"""ACME's model pipeline, rebuilt. Each control is a constructor flag so you can switch it
off and watch which attack comes back.

Part A  SecureTrainingPipeline   (data and model poisoning, LLM05:2026)
    P1  Provenance gate: approved sources only, and the batch digest must match the
        digest recorded at approval (detects tampering after review).        HARD
    P2  Data validation: quarantine samples with rare "trigger candidate" words and
        samples whose label contradicts a trusted reference model.           SOFT (statistical)
    P3  Release gate: clean accuracy and a backdoor scan (append candidate
        triggers to known phishing; block if labels flip).                   HARD gate on a test

Part B  SecureModelAPI           (extraction / model theft, LLM06:2026)
    E1  Query budget per key per day                                          HARD
    E2  Rate limit per key (token bucket, injectable clock)                    HARD
    E3  Output minimization: label only, no probabilities                      HARD
    E4  Extraction-pattern detector: many very short probe queries -> block    SOFT
    E5  Watermark: a keyed, secret ~5% of answers are deliberately flipped and
        logged, so a copied model can be recognized later (verify_watermark)  PROCESS / evidence

Part C  SecureHelpdesk           (misinformation and overreliance, LLM07:2026)
    G1  Retrieve from APPROVED knowledge-base documents only                    HARD
    G2  Every citation must be one of the retrieved documents                  HARD
    G3  Every number in the answer must appear in a cited document             HARD
    G4  Word-overlap support check between answer and cited text               SOFT
    G5  High-stakes topics go to a human, with a disclaimer                    HARD (routing)
    Any failed check -> abstain and hand off. Never show an unverified answer.

Part D  SecureModelLoader        (supply chain, LLM04:2026)
    S1  Name AND version must be pinned in the AI-BOM (no "latest")           HARD
    S2  Publisher must be trusted                                             HARD
    S3  SHA-256 of the bytes must match the AI-BOM                            HARD
    S4  Safe formats only; pickle rejected by declared format AND magic bytes  HARD

Part E  CodeGate                 (insecure AI-generated code, LLM10:2026)
    Static review with ``ast``: unapproved imports (hallucinated or slopsquatted
    packages), eval/exec, shell=True, unsafe deserialization. Code is never run here.

This file imports nothing from its sibling lab files: data and models are injected.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable

TOKEN_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def _tokens(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


def batch_digest(samples: list) -> str:
    """Same canonical form as used when the batch was approved."""
    canonical = json.dumps(sorted([list(s) for s in samples]), separators=(",", ":"),
                           ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


# =========================================================================================
# Part A: poisoning
# =========================================================================================

@dataclass
class TrainingReport:
    released: bool
    model: Any = None
    rejected_batches: list[str] = field(default_factory=list)
    quarantined: list[tuple[str, str, str]] = field(default_factory=list)  # (text, label, why)
    gate_failures: list[str] = field(default_factory=list)
    clean_accuracy: float = 0.0
    worst_trigger: tuple[str, float] = ("", 0.0)


@dataclass
class SecureTrainingPipeline:
    model_factory: Callable[[], Any]
    approved_sources: set[str]
    approved_digests: dict[str, str]
    reference_samples: list[tuple[str, str]]      # small, trusted, human-reviewed seed set
    test_set: list[tuple[str, str]]               # held out, never trained on
    held_out_target: list[str]                    # held-out phishing used by the backdoor scan
    provenance: bool = True
    validate: bool = True
    release_gate: bool = True
    min_accuracy: float = 0.9
    max_flip_rate: float = 0.2
    rare_min_count: int = 3
    conflict_confidence: float = 0.9

    # ---- P1 -------------------------------------------------------------------------
    def _check_provenance(self, batch: dict) -> str | None:
        if batch["source"] not in self.approved_sources:
            return f"source {batch['source']!r} is not approved"
        expected = self.approved_digests.get(batch["batch_id"])
        if expected is None:
            return f"batch {batch['batch_id']!r} was never approved"
        if batch_digest(batch["samples"]) != expected:
            return f"batch {batch['batch_id']!r} changed after approval (digest mismatch)"
        return None

    # ---- P2 -------------------------------------------------------------------------
    def _validate(self, samples: list[tuple[str, str]]) -> tuple[list, list]:
        reference = self.model_factory().train(self.reference_samples)
        known = {t for text, _ in self.reference_samples for t in _tokens(text)}
        by_token: dict[str, Counter] = {}
        for text, label in samples:
            for t in set(_tokens(text)) - known:
                by_token.setdefault(t, Counter())[label] += 1
        suspicious = {t for t, c in by_token.items()
                      if sum(c.values()) >= self.rare_min_count
                      and max(c.values()) / sum(c.values()) >= 0.9}
        keep, quarantined = [], []
        for text, label in samples:
            rare = suspicious & set(_tokens(text))
            if rare:
                quarantined.append((text, label, f"rare trigger candidate {sorted(rare)}"))
                continue
            proba = reference.predict_proba(text)
            predicted = max(proba, key=proba.get)
            if predicted != label and proba[predicted] >= self.conflict_confidence:
                quarantined.append((text, label, f"label conflicts with reference ({predicted})"))
                continue
            keep.append((text, label))
        return keep, quarantined

    # ---- P3 -------------------------------------------------------------------------
    def _candidate_triggers(self, samples: list[tuple[str, str]]) -> set[str]:
        """Groups of words that are new compared with the trusted reference data and appear
        together in one sample. A backdoor trigger has to be learned from somewhere."""
        known = {t for text, _ in self.reference_samples for t in _tokens(text)}
        cands = set()
        for text, _ in samples:
            new = sorted(set(_tokens(text)) - known)
            if new:
                cands.add(" ".join(new))
                cands.update(new)
        return cands

    def _release_gate(self, model: Any, samples: list, report: TrainingReport) -> None:
        acc = sum(model.predict(t) == lb for t, lb in self.test_set) / len(self.test_set)
        report.clean_accuracy = acc
        if acc < self.min_accuracy:
            report.gate_failures.append(f"clean accuracy {acc:.0%} < {self.min_accuracy:.0%}")
        worst = ("", 0.0)
        for trig in sorted(self._candidate_triggers(samples)):
            flips = sum(model.predict(f"{t} {trig}") != "phishing" for t in self.held_out_target)
            rate = flips / len(self.held_out_target)
            if rate > worst[1]:
                worst = (trig, rate)
        report.worst_trigger = worst
        if worst[1] > self.max_flip_rate:
            report.gate_failures.append(
                f"backdoor suspected: adding {worst[0]!r} flips {worst[1]:.0%} of known phishing")

    def train(self, batches: list[dict]) -> TrainingReport:
        report = TrainingReport(released=False)
        samples: list[tuple[str, str]] = []
        for batch in batches:
            problem = self._check_provenance(batch) if self.provenance else None
            if problem:
                report.rejected_batches.append(f"{batch['batch_id']}: {problem}")
                continue
            samples.extend(tuple(s) for s in batch["samples"])
        if self.validate:
            samples, report.quarantined = self._validate(samples)
        model = self.model_factory().train(samples)
        if self.release_gate:
            self._release_gate(model, samples, report)
        report.released = not report.gate_failures
        report.model = model if report.released else None
        return report


# =========================================================================================
# Part B: extraction
# =========================================================================================

@dataclass
class SecureModelAPI:
    model: Any
    budget_per_key: int | None = 25            # E1 (None = off)
    rate_capacity: int | None = 10             # E2 burst size (None = off)
    rate_refill_per_sec: float = 1.0
    labels_only: bool = True                   # E3
    detect: bool = True                        # E4
    watermark_key: bytes | None = None         # E5 (None = off); keep it in a secrets manager
    watermark_rate: float = 0.05
    clock: Callable[[], float] = time.monotonic
    used: Counter = field(default_factory=Counter)
    short_queries: Counter = field(default_factory=Counter)
    blocked_keys: set[str] = field(default_factory=set)
    events: list[dict] = field(default_factory=list)
    watermark_log: list[tuple[str, str, str]] = field(default_factory=list)  # (key, text, label)
    _bucket: dict[str, tuple[float, float]] = field(default_factory=dict)

    def _rate_ok(self, key: str) -> bool:
        if self.rate_capacity is None:
            return True
        now = self.clock()
        tokens, last = self._bucket.get(key, (float(self.rate_capacity), now))
        tokens = min(self.rate_capacity, tokens + (now - last) * self.rate_refill_per_sec)
        ok = tokens >= 1
        self._bucket[key] = (tokens - 1 if ok else tokens, now)
        return ok

    def _is_watermarked(self, text: str) -> bool:
        if not self.watermark_key:
            return False
        mac = hmac.new(self.watermark_key, " ".join(_tokens(text)).encode(), hashlib.sha256)
        return int.from_bytes(mac.digest()[:4], "big") / 2**32 < self.watermark_rate

    def query(self, api_key: str, text: str) -> dict:
        if api_key in self.blocked_keys:
            return {"error": "key blocked pending review"}
        if self.budget_per_key is not None and self.used[api_key] >= self.budget_per_key:
            self.events.append({"event": "quota_exceeded", "key": api_key})
            return {"error": "daily query budget exceeded"}
        if not self._rate_ok(api_key):
            self.events.append({"event": "rate_limited", "key": api_key})
            return {"error": "rate limited, retry later"}
        self.used[api_key] += 1

        if self.detect:
            if len(_tokens(text)) <= 2:
                self.short_queries[api_key] += 1
            # Real customers send whole messages. Many 1-2 word queries look like someone
            # probing the model word by word to measure each word's weight.
            if self.short_queries[api_key] >= 8 and \
                    self.short_queries[api_key] / self.used[api_key] >= 0.5:
                self.blocked_keys.add(api_key)
                self.events.append({"event": "extraction_suspected", "key": api_key,
                                    "queries": self.used[api_key]})
                return {"error": "key blocked pending review"}

        label = self.model.predict(text)
        if self._is_watermarked(text):
            label = "safe" if label == "phishing" else "phishing"
            self.watermark_log.append((api_key, text, label))
        if self.labels_only:
            return {"label": label}
        proba = self.model.predict_proba(text)
        if self._is_watermarked(text):
            proba = {"phishing": proba["safe"], "safe": proba["phishing"]}
        return {"label": label, "scores": {k: round(v, 4) for k, v in proba.items()}}


def verify_watermark(suspect_predict: Callable[[str], str],
                     watermark_log: list[tuple[str, str, str]],
                     min_samples: int = 5, threshold: float = 0.5) -> dict:
    """Does a suspect model reproduce our deliberately wrong (watermarked) answers?

    An independent model agrees with them rarely (they are wrong on purpose). A model
    trained on our API's answers tends to copy them. Evidence, not proof: combine it with
    API logs, account data and legal review.
    """
    n = len(watermark_log)
    if n < min_samples:
        return {"verdict": "inconclusive", "samples": n, "match_rate": None}
    matches = sum(suspect_predict(text) == label for _, text, label in watermark_log)
    rate = matches / n
    verdict = "likely derived from our model" if rate >= threshold else "no evidence of copying"
    return {"verdict": verdict, "samples": n, "match_rate": rate}


# =========================================================================================
# Part C: misinformation and overreliance
# =========================================================================================

STOP = {"the", "a", "an", "is", "are", "can", "i", "my", "for", "of", "to", "do", "you",
        "what", "how", "in", "on", "and", "or", "it", "be", "get", "after", "with", "your"}
CITATION_RE = re.compile(r"\[([a-z0-9-]+)\]")
NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")
ABSTAIN = ("I could not confirm this in ACME's approved policies, so I won't guess. "
           "I have passed your question to a human agent.")
HANDOFF = ("This question needs a qualified professional. I am an AI assistant and cannot "
           "give medical, legal, tax or investment advice. A human agent will contact you.")


def _content(text: str) -> set[str]:
    return {t for t in _tokens(text) if t not in STOP and len(t) > 2}


@dataclass
class HelpdeskAnswer:
    text: str
    status: str                      # grounded | abstained | handoff
    citations: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class SecureHelpdesk:
    llm: Any
    knowledge_base: dict[str, dict]
    high_stakes_topics: set[str] = field(default_factory=set)
    approved_only: bool = True        # G1
    check_citations: bool = True      # G2
    check_numbers: bool = True        # G3
    check_support: bool = True        # G4
    route_high_stakes: bool = True    # G5
    min_support: float = 0.6
    log: list[dict] = field(default_factory=list)

    def _retrieve(self, question: str) -> dict[str, str]:
        q = _content(question)
        scored = []
        for doc_id, doc in self.knowledge_base.items():
            if self.approved_only and not doc["approved"]:
                continue
            overlap = len(q & _content(doc["text"]))
            if overlap >= 2:
                scored.append((overlap, doc_id))
        return {d: self.knowledge_base[d]["text"] for _, d in sorted(scored, reverse=True)[:2]}

    def answer(self, question: str) -> HelpdeskAnswer:
        if self.route_high_stakes and _content(question) & self.high_stakes_topics:
            result = HelpdeskAnswer(HANDOFF, "handoff", reasons=["high-stakes topic"])
            self.log.append({"question": question, "status": result.status})
            return result

        docs = self._retrieve(question)
        context = "\n".join(f"[doc:{d}] {t}" for d, t in docs.items())
        draft = self.llm.complete([
            {"role": "system", "content": "Answer ONLY from the context and cite it as [doc-id]. "
                                          "If the context does not answer, say you don't know."},
            {"role": "user", "content": f"<context>\n{context}\n</context>"},
            {"role": "user", "content": question},
        ])
        cites = CITATION_RE.findall(draft)
        reasons = []
        if self.check_citations:
            if not cites:
                reasons.append("no citation")
            for c in cites:
                if c not in docs:
                    reasons.append(f"citation [{c}] is not a retrieved approved document")
        cited_text = " ".join(docs.get(c, "") for c in cites)
        if self.check_numbers:
            for num in NUMBER_RE.findall(CITATION_RE.sub("", draft)):
                if num not in NUMBER_RE.findall(cited_text):
                    reasons.append(f"number {num} does not appear in the cited source")
        if self.check_support:
            words = _content(CITATION_RE.sub("", draft))
            support = len(words & _content(cited_text)) / (len(words) or 1)
            if support < self.min_support:
                reasons.append(f"only {support:.0%} of the answer's words are in the source")
        if reasons:
            result = HelpdeskAnswer(ABSTAIN, "abstained", reasons=reasons)
        else:
            result = HelpdeskAnswer(draft, "grounded", citations=cites)
        self.log.append({"question": question, "status": result.status, "reasons": reasons})
        return result


# =========================================================================================
# Part D: supply chain
# =========================================================================================

@dataclass
class LoadResult:
    name: str
    version: str
    loaded: bool
    code_executed_on_load: bool = False
    reason: str = ""


@dataclass
class SecureModelLoader:
    hub: dict[tuple[str, str], dict]
    ai_bom: list[dict]
    trusted_publishers: set[str]
    safe_formats: set[str]
    require_pinned: bool = True     # S1
    check_publisher: bool = True    # S2
    check_digest: bool = True       # S3
    check_format: bool = True       # S4
    audit: list[dict] = field(default_factory=list)

    def _reject(self, name: str, version: str, reason: str) -> LoadResult:
        self.audit.append({"event": "model_load_rejected", "name": name, "version": version,
                           "reason": reason})
        return LoadResult(name, version, False, reason=reason)

    def load(self, name: str, version: str) -> LoadResult:
        entry = next((e for e in self.ai_bom if e["name"] == name and e["version"] == version),
                     None)
        if self.require_pinned and (version == "latest" or entry is None):
            return self._reject(name, version, "not pinned in the AI-BOM (name + exact version)")
        artifact = self.hub.get((name, version))
        if artifact is None:
            return self._reject(name, version, "not found in registry")
        if self.check_publisher and artifact["publisher"] not in self.trusted_publishers:
            return self._reject(name, version, f"untrusted publisher {artifact['publisher']!r}")
        if self.check_digest and entry is not None and \
                hashlib.sha256(artifact["data"]).hexdigest() != entry["sha256"]:
            return self._reject(name, version, "SHA-256 does not match the AI-BOM (tampered?)")
        looks_like_pickle = artifact["data"][:1] == b"\x80"
        if self.check_format and (artifact["format"] not in self.safe_formats or looks_like_pickle):
            return self._reject(name, version, "unsafe serialization format (pickle can run code)")
        unsafe = artifact["format"] == "pickle" or looks_like_pickle
        self.audit.append({"event": "model_loaded", "name": name, "version": version})
        return LoadResult(name, version, True, code_executed_on_load=unsafe)


# =========================================================================================
# Part E: AI-generated code
# =========================================================================================

DANGEROUS_CALLS = {"eval", "exec", "compile", "__import__"}
DANGEROUS_ATTRS = {("os", "system"), ("os", "popen"), ("pickle", "loads"), ("pickle", "load"),
                   ("marshal", "loads")}


@dataclass
class CodeReview:
    allowed: bool
    findings: list[str]


@dataclass
class CodeGate:
    approved_packages: set[str]

    def review(self, code: str) -> CodeReview:
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return CodeReview(False, [f"does not parse: {exc.msg}"])   # fail closed
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods = [node.module or ""]
            else:
                mods = []
            for mod in mods:
                top = mod.split(".")[0]
                if top not in self.approved_packages:
                    findings.append(f"unapproved import {top!r}")
            if isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name) and fn.id in DANGEROUS_CALLS:
                    findings.append(f"dangerous call {fn.id}()")
                if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and \
                        (fn.value.id, fn.attr) in DANGEROUS_ATTRS:
                    findings.append(f"dangerous call {fn.value.id}.{fn.attr}()")
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value:
                        findings.append("shell=True (command injection risk)")
        return CodeReview(not findings, findings)
