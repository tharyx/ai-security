"""AI documentation validator: model cards, datasheets (data cards) and user-facing disclosure.

A model card or datasheet that nobody checks drifts into marketing text: "no known
limitations", "TBD", an accuracy number with no test set behind it. This module treats the
documents as data and checks them like code, so a release pipeline can refuse a model whose
documentation is incomplete, unverifiable or contradicts the data documentation.

Finding codes
    DOC-01  required model-card field missing or placeholder text
    DOC-02  no security evaluation (e.g. prompt-injection regression suite)
    DOC-03  an evaluation result misses its own threshold
    DOC-04  an evaluation has no dataset reference, so nobody can reproduce it
    DOC-05  artifact hash missing or malformed, so the approved version cannot be pinned
    DOC-06  no limitations written down ("none known" is not an answer)
    DOC-07  card is stale (older than MAX_CARD_AGE_DAYS)
    DOC-08  training data points to a datasheet that does not exist (lineage break)
    DS-01   required datasheet field missing or placeholder text
    DS-02   personal data without a lawful basis and a DPIA reference
    DS-03   no licence / terms for a third-party or scraped source
    DS-04   classification not propagated: a derived artifact (embeddings, logs, fine-tune
            set) is labelled lower than its source
    DS-05   no retention rule, or "forever"
    TR-01   people talk to the system but are not told it is AI
    TR-02   generated content is published without an AI label
    TR-03   the system makes or shapes decisions about people without an explanation and a
            human-review route

Ideas from: Model Cards for Model Reporting (Mitchell et al., 2019), Datasheets for
Datasets (Gebru et al.), Data Cards (Pushkarna et al., 2022), the OWASP GenAI data-security
guidance on classification propagation, and EU AI Act Art 13 / 50 / 86. The field lists are
this lab's teaching choice, not a standard.

    python 07-ai-governance/lab/doc_validator.py 07-ai-governance/lab/fixtures/documentation_vulnerable.yaml
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml

MAX_CARD_AGE_DAYS = 180
PLACEHOLDERS = {"", "tbd", "todo", "n/a", "na", "none", "unknown", "see wiki", "various", "general use", "-"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CLASS_ORDER = ["public", "internal", "confidential", "restricted"]

MODEL_CARD_REQUIRED = ["model_id", "name", "version", "artifact_sha256", "provider", "owner", "intended_use",
                       "out_of_scope_uses", "training_data", "evaluation", "limitations", "human_oversight",
                       "explanation_available", "last_updated"]
DATASHEET_REQUIRED = ["dataset_id", "name", "version", "owner", "source", "collection_method", "licence",
                      "classification", "contains_personal_data", "retention", "known_gaps_and_biases"]


@dataclass
class Finding:
    code: str
    doc_id: str
    message: str


def _blank(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in PLACEHOLDERS
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def validate_model_card(card: dict, as_of: date, known_datasets: set[str] | None = None) -> list[Finding]:
    did = str(card.get("model_id", "?"))
    out: list[Finding] = []
    add = lambda code, msg: out.append(Finding(code, did, msg))  # noqa: E731

    for f in MODEL_CARD_REQUIRED:
        # 'explanation_available: false' is an honest answer; only None/placeholder is missing.
        if f == "explanation_available" and isinstance(card.get(f), bool):
            continue
        if _blank(card.get(f)):
            add("DOC-01", f"required field '{f}' is missing or placeholder")

    evals = card.get("evaluation") or []
    if evals and not any(e.get("type") == "security" for e in evals):
        add("DOC-02", "no security evaluation (add the prompt-injection / red-team regression result)")
    for e in evals:
        result, threshold = e.get("result"), e.get("threshold")
        if result is None or threshold is None:
            add("DOC-03", f"evaluation '{e.get('name')}' has no result or threshold")
        else:
            ok = result >= threshold if e.get("higher_is_better", True) else result <= threshold
            if not ok:
                add("DOC-03", f"evaluation '{e.get('name')}' = {result} misses threshold {threshold}")
        if _blank(e.get("dataset")):
            add("DOC-04", f"evaluation '{e.get('name')}' has no dataset reference (not reproducible)")

    if not HEX64.match(str(card.get("artifact_sha256", ""))):
        add("DOC-05", "artifact_sha256 missing or not a SHA-256 hex digest: the approved version cannot be pinned")

    lims = [x for x in (card.get("limitations") or []) if not _blank(x) and "no known" not in str(x).lower()]
    if not lims:
        add("DOC-06", "no real limitations listed")

    updated = card.get("last_updated")
    if isinstance(updated, date) and (as_of - updated).days > MAX_CARD_AGE_DAYS:
        add("DOC-07", f"last updated {updated} ({(as_of - updated).days} days > {MAX_CARD_AGE_DAYS})")

    if known_datasets is not None:
        for ds in card.get("training_data") or []:
            if ds != "vendor-provided" and ds not in known_datasets:
                add("DOC-08", f"training data '{ds}' has no datasheet (lineage break)")
    return out


def validate_datasheet(sheet: dict) -> list[Finding]:
    did = str(sheet.get("dataset_id", "?"))
    out: list[Finding] = []
    add = lambda code, msg: out.append(Finding(code, did, msg))  # noqa: E731

    for f in DATASHEET_REQUIRED:
        if f == "contains_personal_data":
            if not isinstance(sheet.get(f), bool):
                add("DS-01", "required field 'contains_personal_data' must be true or false")
        elif _blank(sheet.get(f)):
            add("DS-01", f"required field '{f}' is missing or placeholder")

    if sheet.get("contains_personal_data") is True and (_blank(sheet.get("lawful_basis"))
                                                          or _blank(sheet.get("dpia_ref"))):
        add("DS-02", "personal data without a lawful basis and a DPIA reference")

    if sheet.get("source_type") in {"third_party", "web_scraped"} and _blank(sheet.get("licence")):
        add("DS-03", f"{sheet.get('source_type')} source with no licence or terms recorded")

    src = str(sheet.get("classification", "")).lower()
    if src in CLASS_ORDER:
        for d in sheet.get("derived_artifacts") or []:
            dc = str(d.get("classification", "")).lower()
            if dc not in CLASS_ORDER or CLASS_ORDER.index(dc) < CLASS_ORDER.index(src):
                add("DS-04", f"derived artifact '{d.get('name')}' is '{dc or 'unlabelled'}' but its source is "
                             f"'{src}': labels must follow the data into embeddings, logs and fine-tune sets")

    retention = str(sheet.get("retention", "")).lower()
    if _blank(sheet.get("retention")) or "forever" in retention or "indefinite" in retention:
        add("DS-05", "no retention rule (or 'forever')")
    return out


def check_disclosure(system: dict) -> list[Finding]:
    """User-facing transparency: what people are told, and what they can do about a decision."""
    sid = str(system.get("system_id", "?"))
    d = system.get("disclosure") or {}
    out: list[Finding] = []
    if system.get("interacts_with_people") and _blank(d.get("ai_notice")):
        out.append(Finding("TR-01", sid, "people interact with the system but no 'you are talking to AI' notice"))
    if system.get("publishes_generated_content") and not d.get("content_label"):
        out.append(Finding("TR-02", sid, "generated content is published without an AI-generated label"))
    if system.get("decisions_about_people"):
        notice = d.get("decision_notice") or {}
        if not (notice.get("main_reasons") and notice.get("human_review_route")):
            out.append(Finding("TR-03", sid, "decisions about people with no explanation of main reasons "
                                             "and no route to a human review"))
    return out


def validate_pack(pack: dict, as_of: date) -> list[Finding]:
    """Validate a documentation pack: {'datasheets': [...], 'model_cards': [...], 'systems': [...]}."""
    sheets = pack.get("datasheets") or []
    known = {s.get("dataset_id") for s in sheets}
    findings: list[Finding] = []
    for s in sheets:
        findings += validate_datasheet(s)
    for c in pack.get("model_cards") or []:
        findings += validate_model_card(c, as_of, known)
    for sysd in pack.get("systems") or []:
        findings += check_disclosure(sysd)
    return findings


def main() -> None:
    p = argparse.ArgumentParser(description="Validate model cards, datasheets and disclosures.")
    p.add_argument("pack", help="YAML documentation pack (see fixtures/documentation_*.yaml)")
    p.add_argument("--as-of", default="2026-11-15")
    args = p.parse_args()
    pack = yaml.safe_load(Path(args.pack).read_text(encoding="utf-8"))
    findings = validate_pack(pack, date.fromisoformat(args.as_of))
    for f in findings:
        print(f"{f.code:6} {f.doc_id:8} {f.message}")
    print(f"{len(findings)} finding(s)")


if __name__ == "__main__":
    main()
