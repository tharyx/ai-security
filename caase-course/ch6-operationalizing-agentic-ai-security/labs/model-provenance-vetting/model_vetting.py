"""Vet an open-weight model's provenance before routing production traffic to it.

Inputs: a model card (dict), the hashes you computed yourself from the files you
downloaded, and a policy. Output: a routing decision.

  production  safe to route real traffic (still behind guardrails and monitoring)
  sandbox     usable only for evaluation / non-sensitive traffic
  reject      do not use

Everything here is synthetic: no files are downloaded, names are fictional.
Licence names and the allowlist are examples; your legal team owns the real list.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

PICKLE_SUFFIXES = (".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Policy:
    org_allowlist: tuple[str, ...] = ("example-lab", "open-models-foundation")
    license_allow: tuple[str, ...] = ("apache-2.0", "mit")
    license_review: tuple[str, ...] = ("llama-community", "gemma-terms", "openrail-m")  # needs legal read
    min_eval: dict = field(default_factory=lambda: {"injection_resistance": 0.70, "harmful_refusal": 0.85})


@dataclass
class Decision:
    route: str
    reasons: list[str]

    @property
    def rejected(self) -> bool:
        return self.route == "reject"


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def vet(card: dict, observed_hashes: dict[str, str], policy: Policy | None = None) -> Decision:
    p = policy or Policy()
    reject: list[str] = []
    sandbox: list[str] = []

    # 1. integrity: hashes we computed vs hashes the publisher declares
    declared = card.get("files", {})
    if not declared:
        sandbox.append("no published file hashes to compare against")
    for name, h in declared.items():
        if observed_hashes.get(name) != h:
            reject.append(f"hash mismatch for {name}")
    for name in observed_hashes:
        if name not in declared:
            reject.append(f"unexpected file {name} not in the published manifest")

    # 2. format safety
    for name in list(declared) + list(observed_hashes):
        if name.lower().endswith(PICKLE_SUFFIXES):
            reject.append(f"{name}: pickle-based format can execute code on load (use safetensors)")
    if card.get("requires_trust_remote_code"):
        sandbox.append("requires trust_remote_code (runs publisher code): review it first")

    # 3. source
    org = card.get("source_org", "")
    if org not in p.org_allowlist:
        near = [a for a in p.org_allowlist if _lev(org, a) <= 2]
        if near:
            reject.append(f"org '{org}' looks like a typosquat of '{near[0]}'")
        else:
            sandbox.append(f"org '{org}' not on the allowlist")
    if not card.get("model_card_present"):
        sandbox.append("no model card")
    if not card.get("training_data_disclosed"):
        sandbox.append("training data not disclosed")

    # 4. licence
    lic = str(card.get("license", "")).lower()
    if lic in p.license_allow:
        pass
    elif lic in p.license_review:
        sandbox.append(f"licence '{lic}' needs legal review for production use")
    else:
        reject.append(f"licence '{lic or 'missing'}' not allowed for production")

    # 5. evals: must exist, must meet minimums
    ev = card.get("evals", {})
    for k, minimum in p.min_eval.items():
        if k not in ev:
            sandbox.append(f"missing eval: {k}")
        elif ev[k] < minimum:
            sandbox.append(f"eval {k}={ev[k]} below minimum {minimum}")

    if reject:
        return Decision("reject", reject + sandbox)
    if sandbox:
        return Decision("sandbox", sandbox)
    return Decision("production", ["all checks passed"])
