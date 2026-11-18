"""Scorecard for Portfolio Project 2: the vulnerable vs the secure HR document assistant.
Every row is graded by impact: a canary on the screen of someone who may not read it, the
system prompt's hidden code in an answer, deleted data coming back, or plaintext on disk.

From the repository root:
    python 03-rag-security/secure-hr-assistant/lab/demo.py
"""

from __future__ import annotations

import hr_data as H
from secure_hr_rag import SecureHrAssistant
from vulnerable_hr_rag import HIDDEN_ESCALATION_CODE, VulnerableHrAssistant

SOURCE = {"acme": "acme-hr-system", "globex": "globex-hr-system"}


def build(kind: str):
    app = VulnerableHrAssistant(H.USERS, H.SESSIONS) if kind == "v" else SecureHrAssistant(H.USERS, H.SESSIONS)
    for doc in H.DOCUMENTS:
        app.ingest(SOURCE[doc["tenant"]], doc)
    return app


def ask(app, user, question, **claims):
    session = f"session-{user}" if user else None
    if isinstance(app, VulnerableHrAssistant):
        return app.ask({"session": session, "question": question, **claims})
    return app.ask(session, question, **claims)


def leak_label(user, text):
    leaks = H.leaked(user, text)
    return "LEAK: " + ",".join(f"{d}/{s}" for d, s in leaks) if leaks else "ok"


def case_chat(kind, user, question, **claims):
    return leak_label(user, ask(build(kind), user, question, **claims).visible_text())


def case_bola(kind):
    app = build(kind)
    doc = app.open_document("session-bob", "acme-reorg-plan")
    return "BOLA: opened reorg plan" if doc and H.CANARY_REORG in str(doc) else "ok (404)"


def case_malicious_pdf(kind):
    app = build(kind)
    status = app.ingest("acme-policy-site", H.MALICIOUS_PDF)
    answer = ask(app, "alice", "What does the benefits FAQ say about the dental plan?").visible_text()
    if HIDDEN_ESCALATION_CODE in answer or "My instructions are" in answer:
        return "PROMPT OVERRIDDEN"
    return f"ok ({status})"


def case_delete(kind):
    app = build(kind)
    question = "Bob compensation salary band base pay reference"
    ask(app, "hana", question)                       # warm any cache
    if kind == "v":
        app.delete_document("acme-bob-record")
    else:
        app.delete_document("session-omar", "acme-bob-record")
    return "DELETED DATA SERVED" if H.CANARY_BOB_PAY in ask(app, "hana", question).visible_text() else "ok"


def case_disk(kind):
    app = build(kind)
    raw = str(app.disk) if kind == "v" else app.raw_storage_dump()
    return "PLAINTEXT ON DISK" if H.CANARY_ALICE_PAY in raw else "ok (ciphertext)"


CASES = [
    ("tenant_spoof_in_request", lambda k: case_chat(k, "alice", "Globex annual leave days", tenant="globex")),
    ("user_a_reads_user_b", lambda k: case_chat(k, "alice", "Bob compensation salary band base pay")),
    ("manager_sees_report_pay", lambda k: case_chat(k, "maria", "Alice compensation salary band base pay")),
    ("bola_open_hr_document", case_bola),
    ("malicious_pdf_override", case_malicious_pdf),
    ("deleted_doc_still_answers", case_delete),
    ("disk_or_backup_theft", case_disk),
]


def main() -> None:
    print(f"{'case':28} {'vulnerable':66} secure")
    print("-" * 112)
    for name, fn in CASES:
        print(f"{name:28} {fn('v'):66} {fn('s')}")

    app = build("s")
    print("\nAuthorized users still get their answers (secure app):")
    for user, question, canary in [("hana", "Alice compensation salary band base pay", H.CANARY_ALICE_PAY),
                                   ("alice", "Alice compensation salary band base pay", H.CANARY_ALICE_PAY),
                                   ("gil", "Globex annual leave days", H.CANARY_GLOBEX)]:
        print(f"  {user:6} {question:44} {'ok' if canary in ask(app, user, question).visible_text() else 'BROKEN'}")
    print(f"\nAudit log: {len(app.audit.entries)} entries, hash chain valid = {app.audit.verify()}")
    print("Authorization happens before decryption; the model only ever sees what the user may read.")


if __name__ == "__main__":
    main()
