"""Demo: threat-model the sample chatbot, then harden it and compare.

    python caisp-course/ch5-threat-modeling-ai-systems/labs/threat-model-ai-system/demo.py
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tm_tool as tm  # noqa: E402

HERE = Path(__file__).resolve().parent


def summary(register):
    counts = Counter(t.residual_severity for t in register if t.status == "open")
    return {k: counts.get(k, 0) for k in reversed(tm.SEVERITY_ORDER)}


def main() -> None:
    lib = tm.load_library()
    dfd = tm.load_dfd(HERE / "dfd.yaml")
    print(f"System: {dfd.system}")
    print("DFD issues:", [f"{i.level}: {i.message}" for i in tm.validate_dfd(dfd)] or "none")
    register = tm.build_register(dfd, lib)
    print(f"\nSTRIDE per element produced {len(register)} threats. Top 8:\n")
    print(tm.to_table(register, top=8))
    print("\nOpen threats by residual severity:", summary(register))

    raw = yaml.safe_load((HERE / "dfd.yaml").read_text(encoding="utf-8"))
    for e in raw["elements"]:
        if e["id"] in ("orchestrator", "ticket_tool"):
            e["controls"] = sorted(set(e["controls"]) | {"tool_authz", "human_approval",
                                                         "schema_validation", "rate_limit", "token_budget"})
        if e["id"] in ("retriever", "vdb"):
            e["controls"] = sorted(set(e["controls"]) | {"acl_filter", "integrity_check"})
    for e in raw["elements"]:
        if e["id"] in ("orchestrator", "ingest", "ticket_tool", "logs"):
            e["controls"] = sorted(set(e["controls"]) | {"audit_log", "integrity_check", "redaction"})
    for f in raw["flows"]:
        if f["id"] in ("F6", "F8", "F9", "F11", "F12"):
            f["controls"] = sorted(set(f.get("controls", [])) | {
                "schema_validation", "tool_authz", "integrity_check", "output_encoding"})
        if f["id"] in ("F3", "F13", "F12"):
            f["controls"] = sorted(set(f.get("controls", [])) | {"tls", "rate_limit"})
    hardened = tm.build_register(tm.DFD.model_validate(raw), lib)
    print("After adding tool_authz, human_approval, validation, limits, ACL filter, flow checks:")
    print("Open threats by residual severity:", summary(hardened))
    print("Blocking (open High/Critical):", len(tm.blocking(register)), "->", len(tm.blocking(hardened)))

    print("\nMermaid DFD (paste into https://mermaid.live):\n")
    print(tm.to_mermaid(dfd))


if __name__ == "__main__":
    main()
