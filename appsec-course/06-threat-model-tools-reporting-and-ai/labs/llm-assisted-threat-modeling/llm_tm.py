"""LLM-assisted threat modeling (the STRIDE GPT / AI-assistant pattern), fully offline.

Pipeline:
  architecture (JSON) -> redact() -> build_prompt() -> model.complete() -> review() -> human sign-off

* StubThreatLLM is a deterministic stand-in for a real model. Its draft is realistic: mostly useful, but with a
  hallucinated component, a non-STRIDE category, a duplicate, and gaps (no Repudiation, one boundary flow missed).
* aisec_lab.MockLLM is a deliberately gullible model: an instruction hidden in a design document hijacks it,
  which shows why the output must be validated as data, never trusted as text.
* review() is the human-in-the-loop gate: schema, grounding (components must exist), STRIDE names, duplicates
  and coverage against a STRIDE-per-element baseline. accept() also requires a named human reviewer.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

STRIDE = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service",
          "Elevation of Privilege"]
# Minimum coverage we expect from any draft (teaching baseline, after STRIDE-per-element).
BASELINE = {"process": {"Spoofing", "Tampering", "Elevation of Privilege"},
            "datastore": {"Information Disclosure", "Tampering"},
            "boundary_flow": {"Information Disclosure"}}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.(?:corp|internal|local)\b", re.I)
SECRET_RE = re.compile(r"\b(?:key|token|password|secret)\s*[=:]\s*\S+", re.I)


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def redact(text: str) -> str:
    """Remove details an external model does not need: internal IPs, internal hostnames, secrets."""
    text = SECRET_RE.sub("[REDACTED-SECRET]", text)
    text = IP_RE.sub("[REDACTED-IP]", text)
    return HOST_RE.sub("[REDACTED-HOST]", text)


def build_prompt(arch: dict, redact_first: bool = True) -> list[dict]:
    desc = arch["description"]
    if redact_first:
        desc = redact(desc)
    elements = ", ".join(f"{e['name']} ({e['kind']})" for e in arch["elements"])
    flows = "; ".join(f"{f['from']} -> {f['to']}" + (" [crosses boundary]" if f.get("crosses_boundary") else "")
                      for f in arch["flows"])
    return [
        {"role": "system", "content": "You are a threat modeling assistant. Reply ONLY with a JSON list of objects "
                                      "with keys component, stride, title, mitigation. Use STRIDE category names."},
        {"role": "user", "content": f"Elements: {elements}\nData flows: {flows}\n<document>{desc}</document>"},
    ]


@dataclass
class StubThreatLLM:
    """Deterministic drafting model. Records every prompt so tests can check for leaks."""
    name: str = "stub-threat-drafter-1"
    calls: list = field(default_factory=list)

    def complete(self, messages: list[dict]) -> str:
        self.calls.append([dict(m) for m in messages])
        draft = [
            {"component": "Web App", "stride": "Spoofing", "title": "Credential stuffing on login",
             "mitigation": "MFA, breached-password check, rate limits"},
            {"component": "Web App", "stride": "Tampering", "title": "Stored XSS in reviews",
             "mitigation": "output encoding and CSP"},
            {"component": "Orders API", "stride": "Elevation of Privilege", "title": "BOLA on order ids",
             "mitigation": "owner check on every query"},
            {"component": "Orders API", "stride": "Elevation of Privilege", "title": "BOLA on order IDs",
             "mitigation": "owner check"},
            {"component": "Orders DB", "stride": "Information Disclosure", "title": "Unencrypted backups",
             "mitigation": "encrypt backups"},
            {"component": "Redis cache", "stride": "Information Disclosure", "title": "Cache without auth",
             "mitigation": "enable AUTH and TLS"},
            {"component": "Customer -> Web App", "stride": "Information Disclosure", "title": "Sniffing on public Wi-Fi",
             "mitigation": "TLS 1.2+ and HSTS"},
            {"component": "Web App", "stride": "Phishing", "title": "Users get phished",
             "mitigation": "security awareness"},
        ]
        return json.dumps(draft)


@dataclass
class Review:
    accepted: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)       # block the draft
    rejected: list[str] = field(default_factory=list)     # items thrown out
    missing: list[str] = field(default_factory=list)      # coverage gaps a human must fill

    @property
    def blocking(self) -> bool:
        return bool(self.errors or self.missing)


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def review(draft_text: str, arch: dict) -> Review:
    r = Review()
    try:
        items = json.loads(draft_text)
        if not isinstance(items, list):
            raise ValueError("not a list")
    except (json.JSONDecodeError, ValueError) as e:
        r.errors.append(f"output is not a JSON list of threats ({e}); possible prompt injection or format drift")
        return r
    known = {e["name"]: e["kind"] for e in arch["elements"]}
    flows = {f"{f['from']} -> {f['to']}": f for f in arch["flows"]}
    seen = set()
    for it in items:
        if not isinstance(it, dict) or not {"component", "stride", "title", "mitigation"} <= set(it):
            r.rejected.append(f"malformed item: {it!r}"[:80])
            continue
        comp, stride = it["component"], it["stride"]
        if comp not in known and comp not in flows:
            r.rejected.append(f"HALLUCINATED component '{comp}': not in the architecture")
            continue
        if stride not in STRIDE:
            r.rejected.append(f"INVALID category '{stride}' for '{it['title']}'")
            continue
        key = (comp, stride, _norm(it["title"]))
        if key in seen:
            r.rejected.append(f"DUPLICATE '{it['title']}' on {comp}")
            continue
        seen.add(key)
        r.accepted.append(it)
    covered = {(i["component"], i["stride"]) for i in r.accepted}
    for name, kind in known.items():
        for cat in sorted(BASELINE.get(kind, set())):
            if (name, cat) not in covered:
                r.missing.append(f"{name}: no {cat} threat considered")
    for name, f in flows.items():
        if f.get("crosses_boundary"):
            for cat in sorted(BASELINE["boundary_flow"]):
                if (name, cat) not in covered:
                    r.missing.append(f"{name}: no {cat} threat considered")
    if not any(i["stride"] == "Repudiation" for i in r.accepted):
        r.missing.append("whole model: no Repudiation threat at all (audit logging?)")
    return r


def accept(rev: Review, reviewer: str | None) -> bool:
    """A draft becomes part of the threat model only when nothing blocks it AND a named human signed it off."""
    return not rev.blocking and bool(reviewer and reviewer.strip())


def leaked(calls: list, needles: list[str]) -> list[str]:
    sent = json.dumps(calls)
    return [n for n in needles if n in sent]
