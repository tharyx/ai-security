"""Map attacker actions to MITRE ATLAS-style tactics with a transparent keyword classifier.

The 14 tactics are the course's list, in kill-chain order. ATLAS renamed two of them
(ML Model Access -> AI Model Access, ML Attack Staging -> AI Attack Staging; verify the
current names and any later renames at atlas.mitre.org). ``normalize_tactic`` accepts both.

This is a teaching tool, not a detector: a keyword list is easy to read, easy to test and
easy to fool. Real SOC mapping is done by analysts, often with ML help.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

TACTICS: list[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "ML Model Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Collection",
    "ML Attack Staging",
    "Exfiltration",
    "Impact",
]

ALIASES: dict[str, str] = {
    "ai model access": "ML Model Access",
    "ai attack staging": "ML Attack Staging",
    "ai attack adaptation": "ML Attack Staging",  # reported later rename; verify at source
}

# Lower-case phrases searched as substrings. Longer phrases are more specific and weigh
# more (weight = number of words).
RULES: dict[str, list[str]] = {
    "Reconnaissance": ["reads public", "published papers", "model cards", "learn which", "scans public",
                       "search engines for information", "job adverts", "conference slides"],
    "Resource Development": ["registers a look-alike", "look-alike domain", "buys cloud credits",
                             "host a poisoned", "preparing the malicious", "trains a backdoored",
                             "uploads it to a public"],
    "Initial Access": ["sends a support email", "hidden instructions", "supply chain compromise",
                       "downloads the look-alike", "as a valid account", "sign in to the gateway"],
    "ML Model Access": ["chat endpoint", "product api", "paid api key", "access to the model's outputs",
                        "queries the public", "thousands of queries"],
    "Execution": ["tool call", "executes the embedded", "run a tool", "runs the injected",
                  "loading the unsafe pickle"],
    "Persistence": ["long-term memory", "every future session", "stays active", "backdoor in the account"],
    "Privilege Escalation": ["escalates to admin", "over-permissive role", "admin rights",
                             "higher privileges"],
    "Defense Evasion": ["renames files", "obfuscates", "does not detect", "look legitimate",
                        "evade the detector", "evade detection", "bypass the filter"],
    "Credential Access": ["steals the cloud", "access keys and tokens", "extracts the credentials",
                          "api key for the gateway", "harvest"],
    "Discovery": ["lists the storage", "which tools, plugins", "discovering its capabilities",
                  "enumerate"],
    "Collection": ["gathers customer records", "gather training datasets", "prompt logs",
                   "collects documents"],
    "ML Attack Staging": ["proxy model", "adversarial examples", "craft adversarial", "craft the poisoned",
                          "verify the attack offline"],
    "Exfiltration": ["out to a server", "to a server they own", "exfiltration", "markdown image",
                     "sends the data"],
    "Impact": ["financial loss", "exhaust the monthly budget", "make the service unavailable",
               "causing financial", "reputational damage", "flood of expensive requests"],
}


def normalize_tactic(name: str) -> str:
    """Return the canonical course tactic name, or raise ValueError."""
    key = name.strip().lower()
    if key in ALIASES:
        return ALIASES[key]
    for tactic in TACTICS:
        if tactic.lower() == key:
            return tactic
    raise ValueError(f"unknown tactic: {name!r}")


def scores(text: str) -> dict[str, int]:
    low = " ".join(text.lower().split())
    out: dict[str, int] = {}
    for tactic, phrases in RULES.items():
        s = sum(len(p.split()) for p in phrases if p in low)
        if s:
            out[tactic] = s
    return out


def classify(text: str) -> str | None:
    """Best-scoring tactic, ties broken by kill-chain order; None if nothing matches."""
    sc = scores(text)
    if not sc:
        return None
    best = max(sc.values())
    return next(t for t in TACTICS if sc.get(t) == best)


def load_incidents(path: Path = HERE / "incidents.json") -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["incidents"]


def all_steps(path: Path = HERE / "incidents.json") -> dict[str, str]:
    return {s["id"]: s["text"] for inc in load_incidents(path) for s in inc["steps"]}


def load_mapping(path: Path) -> dict[str, str]:
    """Load a {step_id: tactic} file; keys starting with '_' are comments."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def grade(mapping: dict[str, str], key: dict[str, str]) -> dict:
    """Compare a mapping with the answer key. Unknown tactic names are reported separately."""
    correct, wrong, unknown_ids, bad_names = [], [], [], []
    for step_id, tactic in mapping.items():
        if step_id not in key:
            unknown_ids.append(step_id)
            continue
        try:
            ok = normalize_tactic(tactic) == normalize_tactic(key[step_id])
        except ValueError:
            bad_names.append(step_id)
            continue
        (correct if ok else wrong).append(step_id)
    missing = [s for s in key if s not in mapping]
    return {"correct": correct, "wrong": wrong, "missing": missing,
            "unknown_ids": unknown_ids, "bad_names": bad_names,
            "score": len(correct), "total": len(key)}


def classifier_mapping() -> dict[str, str]:
    return {sid: (classify(text) or "UNKNOWN") for sid, text in all_steps().items()}


def tactic_coverage(key: dict[str, str]) -> set[str]:
    return {normalize_tactic(t) for t in key.values()}
