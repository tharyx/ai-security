"""LLM hallucination lab: catch fabricated citations, invented package names and ungrounded claims.

Three checks, each a hard control that does not trust the model:

1. Citations: every DOI / "Author (Year)" the answer mentions must exist in a trusted library.
2. Packages: every ``pip install X`` / ``import X`` must be in an approved package index
   (a snapshot of what your organisation allows). Unknown names are possible hallucinations,
   and a hallucinated name is exactly what an attacker may register ("slopsquatting").
3. Grounding: each sentence of a RAG answer must be supported by the retrieved passages.

All data is synthetic. DOIs use the 10.5555 prefix (commonly used for examples).
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from aisec_lab import Message, MockLLM

FIXTURES = Path(__file__).with_name("fixtures")

DOI_RE = re.compile(r"\b10\.\d{4,9}/[^\s,;)\]]+")
AUTHOR_YEAR_RE = re.compile(r"\b([A-Z][a-z]+)(?: et al\.)?,? \((\d{4})\)")
PIP_RE = re.compile(r"pip install\s+([A-Za-z0-9_.-]+)")
IMPORT_RE = re.compile(r"^\s*(?:import|from)\s+([A-Za-z0-9_]+)", re.M)
STOPWORDS = {"the", "a", "an", "is", "are", "of", "to", "and", "in", "on", "for", "with", "by", "at", "it",
             "this", "that", "be", "as", "or", "from", "can", "has", "have", "was", "were"}
STDLIB_OK = {"json", "re", "os", "sys", "pathlib", "typing", "dataclasses", "math", "time"}


def load_json(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# ---------- 1. citations -------------------------------------------------------------------

@dataclass
class CitationFinding:
    kind: str
    text: str
    status: str  # verified | unverified


def check_citations(answer: str, library: list[dict]) -> list[CitationFinding]:
    dois = {e["doi"].lower() for e in library}
    author_years = {(e["first_author"].lower(), str(e["year"])) for e in library}
    out = [CitationFinding("doi", d.rstrip("."), "verified" if d.rstrip(".").lower() in dois else "unverified")
           for d in DOI_RE.findall(answer)]
    for name, year in AUTHOR_YEAR_RE.findall(answer):
        out.append(CitationFinding("author-year", f"{name} ({year})",
                                   "verified" if (name.lower(), year) in author_years else "unverified"))
    return out


# ---------- 2. packages --------------------------------------------------------------------

@dataclass
class PackageFinding:
    name: str
    status: str  # approved | unknown | lookalike
    suggestion: str | None = None


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def check_packages(answer: str, approved: set[str]) -> list[PackageFinding]:
    approved_n = {normalize(a) for a in approved}
    names = {normalize(n) for n in PIP_RE.findall(answer)} | {
        normalize(n) for n in IMPORT_RE.findall(answer) if n not in STDLIB_OK}
    findings = []
    for n in sorted(names):
        if n in approved_n:
            findings.append(PackageFinding(n, "approved"))
            continue
        close = difflib.get_close_matches(n, sorted(approved_n), n=1, cutoff=0.75)
        findings.append(PackageFinding(n, "lookalike" if close else "unknown", close[0] if close else None))
    return findings


# ---------- 3. grounding -------------------------------------------------------------------

def _content_words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOPWORDS and len(w) > 1}


def sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]


@dataclass
class GroundingReport:
    supported: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)

    @property
    def grounded(self) -> bool:
        return not self.unsupported


def check_grounding(answer: str, passages: list[str], threshold: float = 0.6) -> GroundingReport:
    """A sentence is supported when most of its content words, and ALL its numbers, appear in one passage."""
    report = GroundingReport()
    pass_words = [_content_words(p) for p in passages]
    pass_numbers = [set(re.findall(r"\d+(?:\.\d+)?", p)) for p in passages]
    for s in sentences(answer):
        words, numbers = _content_words(s), set(re.findall(r"\d+(?:\.\d+)?", s))
        ok = False
        for pw, pn in zip(pass_words, pass_numbers):
            if words and len(words & pw) / len(words) >= threshold and numbers <= pn:
                ok = True
        (report.supported if ok else report.unsupported).append(s)
    return report


# ---------- a model that hallucinates --------------------------------------------------------

class HallucinatingLLM(MockLLM):
    """Answers confidently even when it has no source. With <context>, MockLLM copies it (grounded)."""

    def complete(self, messages: list[Message]) -> str:
        user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "").lower()
        full = "\n".join(m["content"] for m in messages)
        if "<context>" in full:
            return super().complete(messages)
        if "cite" in user or "reference" in user or "study" in user:
            return ("Yes. Smith et al. (2019) proved this in 'Perfect Prompt Filters', "
                    "doi 10.5555/lab.999. See also Doe (2021).")
        if "package" in user or "library" in user or "install" in user:
            return "Use the helper library: pip install flask-securejwt-utils\n\nimport flask_securejwt_utils"
        if "limit" in user or "how many" in user:
            return "The API allows 5000 requests per minute."
        return super().complete(messages)


@dataclass
class CheckedAnswer:
    text: str
    status: str  # ok | needs-review | blocked
    reasons: list[str]


def answer_with_checks(question: str, llm: MockLLM, *, library: list[dict], approved: set[str],
                       passages: list[str] | None = None) -> CheckedAnswer:
    """The wrapper an application would use: the model proposes, hard checks decide."""
    messages = [{"role": "user", "content": question}]
    if passages:
        messages = [{"role": "user", "content": "<context>" + " ".join(passages) + "</context>\n" + question}]
    text = llm.complete(messages)
    reasons: list[str] = []
    bad_cites = [c.text for c in check_citations(text, library) if c.status == "unverified"]
    bad_pkgs = [p.name for p in check_packages(text, approved) if p.status != "approved"]
    if bad_cites:
        reasons.append("unverified citations: " + ", ".join(bad_cites))
    if bad_pkgs:
        reasons.append("unapproved packages: " + ", ".join(bad_pkgs))
    if passages:
        rep = check_grounding(text.removeprefix("Based on the context: "), passages)
        if not rep.grounded:
            reasons.append("ungrounded sentences: " + str(len(rep.unsupported)))
    if not passages and re.search(r"\d+", text) and not bad_cites:
        reasons.append("numeric claim with no source to check it against")
    if bad_pkgs:
        return CheckedAnswer("[answer withheld]", "blocked", reasons)
    if reasons:
        return CheckedAnswer(text, "needs-review", reasons)
    return CheckedAnswer(text, "ok", [])
