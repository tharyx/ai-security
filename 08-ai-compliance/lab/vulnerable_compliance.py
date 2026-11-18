"""Checkbox compliance: how many teams start, and why auditors and regulators are not impressed.

DO NOT copy this pattern. Every line marked VULN is a failure this lab teaches you to find.
Compare with ai_act_classifier.py, evidence_checker.py and privacy_rights.py.

    python 08-ai-compliance/lab/demo.py
"""

from __future__ import annotations


def naive_classify(answers: dict) -> str:
    """'Is it a chatbot? Then it is limited risk. Otherwise minimal.'"""
    # VULN 1: one question decides everything. Prohibited practices and Annex III are never asked.
    # VULN 2: missing answers silently default to the lowest category.
    # VULN 3: the organization's role (provider, deployer...) is ignored, so obligations are wrong.
    # VULN 4: scope is never checked: it claims EU obligations for systems with no EU link.
    if answers.get("interacts_with_people"):
        return "limited_risk"
    return "minimal_risk"


def naive_evidence_check(controls: list[dict], index: list[dict]) -> dict[str, str]:
    """'We have a document for that control, so it is compliant.'"""
    have = {ev["control"] for ev in index}
    # VULN 5: any one item counts, even if the control needs several kinds of evidence.
    # VULN 6: dates are ignored: last year's export "proves" this year's control.
    # VULN 7: the file is never opened: deleted or edited evidence still counts.
    # VULN 8: a screenshot is accepted where the control needs automated, repeatable evidence.
    return {c["id"]: ("COMPLIANT" if c["id"] in have else "GAP") for c in controls}


def naive_erasure(store, subject_id: str) -> str:
    """'Delete the customer's document, close the ticket.'"""
    # VULN 9: only the source is deleted. Chunks, cache, logs, backups and fine-tuning data remain.
    # VULN 10: no receipt, so there is no evidence of what was (and was not) deleted.
    for doc_id in [d for d, v in store.sources.items() if v["subject_id"] == subject_id]:
        del store.sources[doc_id]
    return "done"
