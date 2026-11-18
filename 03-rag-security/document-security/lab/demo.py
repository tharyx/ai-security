"""Feed every test document to the vulnerable and the secure ingestion pipeline,
then ask the assistant a question and print a scorecard graded by impact.

From the repository root:
    python 03-rag-security/document-security/lab/demo.py
"""

from __future__ import annotations

import attacks
from harness import RagAssistant
from secure_ingest import SecureIngestor
from vulnerable_ingest import EXTRACT_DIR, VulnerableIngestor


def load_base(pipeline) -> None:
    for filename, content, source in attacks.BASE_CORPUS:
        pipeline.ingest(filename, content, source)


def outcome(pipeline, name: str, question: str) -> str:
    """Grade by impact: what could a user or attacker actually get out of the system?"""
    texts = " ".join(c.text for c in pipeline.chunks)
    if name == "zip_bomb":
        return f"EXPANDED {pipeline.bytes_expanded // 2**20} MB" if pipeline.bytes_expanded > 2**20 else "ok"
    if name == "zip_slip":
        escaped = [p for p in getattr(pipeline, "extracted_paths", []) if not p.startswith(EXTRACT_DIR + "/")]
        return "PATH ESCAPED" if escaped else "ok"
    if name == "disguised_executable":
        return "BINARY INDEXED" if "This program cannot be run" in texts else "ok"
    answer = RagAssistant(pipeline.chunks).ask(question)
    if attacks.EVIL_DOMAIN in answer:
        return "POISON SERVED" if name == "poisoned_upload" else "HIJACKED"
    if attacks.PII_NATIONAL_ID in answer or attacks.PII_PHONE in answer:
        return "PII LEAKED"
    return "ok"


def main() -> None:
    print(f"{'case':26} {'vulnerable':16} {'secure':10} secure pipeline decision")
    print("-" * 110)
    for name, (filename, content, source, question) in attacks.CASES.items():
        vuln, sec = VulnerableIngestor(), SecureIngestor()
        load_base(vuln)
        load_base(sec)
        vuln.ingest(filename, content, source)
        result = sec.ingest(filename, content, source)
        v, s = outcome(vuln, name, question), outcome(sec, name, question)
        print(f"{name:26} {v:16} {s:10} {result.status}: {'; '.join(result.reasons) or '-'}")

    vuln, sec = VulnerableIngestor(), SecureIngestor()
    load_base(vuln)
    load_base(sec)
    v = "ok" if "economy" in RagAssistant(vuln.chunks).ask(attacks.BENIGN_QUESTION) else "BROKEN"
    s = "ok" if "economy" in RagAssistant(sec.chunks).ask(attacks.BENIGN_QUESTION) else "BROKEN"
    print(f"{'benign_travel_question':26} {v:16} {s:10} indexed: -")

    print("\nQuarantined files are kept for human review, not deleted: false positives need a way back in.")
    print("Tip: switch a layer off, e.g. SecureIngestor(scan_injection=False), and re-run.")


if __name__ == "__main__":
    main()
