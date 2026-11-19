"""Validator for a protocol-level threat model and control set (Chapter 7, lab 8).

Usage:  python validator.py protocol_threat_model_template.yaml     (lists what is still missing)
        python validator.py example_completed_model.yaml           (passes)
The validator checks structure and completeness; it cannot judge whether your threats are the RIGHT ones.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
LABS = HERE.parent
REPO = HERE.parents[3]
PROTOCOLS = ("a2a", "acp_style", "ucp_style", "mcp")
ATTACK_CLASSES = {"spoofing_identity_forgery", "capability_discovery_abuse", "context_state_injection",
                  "replay_downgrade_mitm", "cross_protocol_confusion"}
CONTROL_TYPES = {"hard", "soft", "process"}
HIGH = 15  # inherent score (likelihood x impact) at or above this needs a hard control


def load(path: Path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def _todos(obj, where="") -> list[str]:
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _todos(v, f"{where}.{k}" if where else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _todos(v, f"{where}[{i}]")
    elif isinstance(obj, str) and "TODO" in obj:
        out.append(f"{where}: still contains TODO")
    return out


def _score(d: dict) -> int:
    return d["likelihood"] * d["impact"]


def validate(model: dict, *, check_test_refs: bool = False) -> list[str]:
    problems = _todos(model)
    pm = model.get("protocol_models", {})
    controls = {c.get("id"): c for c in model.get("controls", [])}
    if len(controls) != len(model.get("controls", [])):
        problems.append("controls: duplicate ids")
    used_controls: set[str] = set()
    classes: set[str] = set()
    stride: set[str] = set()
    ids: list[str] = []
    for proto in PROTOCOLS:
        block = pm.get(proto)
        if not block:
            problems.append(f"{proto}: missing protocol model")
            continue
        if not block.get("assets"):
            problems.append(f"{proto}: no assets")
        if not block.get("trust_boundaries"):
            problems.append(f"{proto}: no trust boundaries")
        threats = block.get("threats", [])
        if len(threats) < 2:
            problems.append(f"{proto}: needs at least 2 threats")
        for t in threats:
            tid = t.get("id", "?")
            ids.append(tid)
            if t.get("attack_class") not in ATTACK_CLASSES:
                problems.append(f"{tid}: attack_class must be one of {sorted(ATTACK_CLASSES)}")
            else:
                classes.add(t["attack_class"])
            if t.get("stride") not in set("STRIDE"):
                problems.append(f"{tid}: stride must be one of S T R I D E")
            else:
                stride.add(t["stride"])
            if not t.get("atlas"):
                problems.append(f"{tid}: missing ATLAS tactic")
            if not re.fullmatch(r"ASI(0[1-9]|10)", str(t.get("asi", ""))):
                problems.append(f"{tid}: asi must look like ASI01..ASI10")
            try:
                inh, res = t["inherent"], t["residual"]
                for d in (inh, res):
                    for k in ("likelihood", "impact"):
                        if not 1 <= d[k] <= 5:
                            problems.append(f"{tid}: {k} must be 1-5")
                if _score(res) > _score(inh):
                    problems.append(f"{tid}: residual risk is higher than inherent risk")
                tc = [controls[c] for c in t.get("controls", []) if c in controls]
                if _score(inh) >= HIGH and not any(c.get("type") == "hard" for c in tc):
                    problems.append(f"{tid}: inherent score {_score(inh)} needs at least one hard control")
                if tc and _score(res) >= _score(inh):
                    problems.append(f"{tid}: has controls but residual risk did not fall")
            except (KeyError, TypeError):
                problems.append(f"{tid}: inherent/residual need likelihood and impact")
            if not t.get("controls"):
                problems.append(f"{tid}: no controls listed")
            for c in t.get("controls", []):
                used_controls.add(c)
                if c not in controls:
                    problems.append(f"{tid}: unknown control {c}")
    if len(set(ids)) != len(ids):
        problems.append("threats: duplicate ids")
    for missing in sorted(ATTACK_CLASSES - classes):
        problems.append(f"model: no threat covers attack class {missing}")
    for missing in sorted(set("STRIDE") - stride):
        problems.append(f"model: no threat uses STRIDE letter {missing}")
    for cid, c in controls.items():
        if c.get("type") not in CONTROL_TYPES:
            problems.append(f"{cid}: type must be hard, soft or process")
        test = str(c.get("test", ""))
        if c.get("type") == "hard" and "::" not in test:
            problems.append(f"{cid}: a hard control must point at a test as path::test_name")
        elif c.get("type") != "hard" and not (test.startswith("manual:") or "::" in test):
            problems.append(f"{cid}: soft/process controls need 'manual: ...' or a test reference")
        if cid not in used_controls:
            problems.append(f"{cid}: control is not used by any threat")
        if check_test_refs and "::" in test and "TODO" not in test:
            problems += _check_ref(cid, test)
    return problems


def _check_ref(cid: str, ref: str) -> list[str]:
    path, name = ref.split("::", 1)
    for base in (LABS, REPO):
        f = base / path
        if f.is_file():
            if f"def {name}(" not in f.read_text(encoding="utf-8"):
                return [f"{cid}: test {name} not found in {path}"]
            return []
    return [f"{cid}: test file {path} not found"]


def coverage_matrix(model: dict) -> dict[str, set[str]]:
    """attack class -> set of protocol areas that cover it."""
    out: dict[str, set[str]] = {c: set() for c in ATTACK_CLASSES}
    for proto, block in model.get("protocol_models", {}).items():
        for t in block.get("threats", []):
            if t.get("attack_class") in out:
                out[t["attack_class"]].add(proto)
    return out


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "protocol_threat_model_template.yaml"
    probs = validate(load(target), check_test_refs=True)
    print(f"{target.name}: {len(probs)} problem(s)")
    for p in probs[:40]:
        print(" -", p)
    sys.exit(1 if probs else 0)
