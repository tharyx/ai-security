"""Run every access-control attack against the vulnerable and the secure RAG app and
print a scorecard. A case is a LEAK when a canary of a document the user may not read
(according to the source system) appears anywhere on their screen: answer or citations.

From the repository root:
    python 03-rag-security/access-control/lab/demo.py
"""

from __future__ import annotations

import attacks
from secure_rag import SecureRagApp
from vulnerable_rag import VulnerableRagApp


def vulnerable():
    return VulnerableRagApp(attacks.INDEX, attacks.USERS, attacks.SESSIONS)


def secure(**flags):
    return SecureRagApp(attacks.INDEX, attacks.USERS, attacks.SESSIONS, attacks.SOURCE_ACL, **flags)


def session_of(user):
    return f"session-{user}" if user else None


SHORT = {"red-hr-salaries": "hr", "red-legacy-import": "legacy",
         "blue-roadmap": "blue", "blue-board-minutes": "board"}


def grade(user, response) -> str:
    leaks = attacks.leaked_canaries(user, response.visible_text())
    return "LEAK: " + ",".join(SHORT[d] for d in leaks) if leaks else "ok"


def main() -> None:
    print(f"{'case':32} {'user':8} {'vulnerable':24} {'secure':8} secure-app events")
    print("-" * 112)
    for name, (user, claims, question) in attacks.ATTACKS.items():
        v = vulnerable().ask({"session": session_of(user), "question": question, **claims})
        app = secure()
        s = app.ask(session_of(user), question, **claims)
        kinds = ",".join(dict.fromkeys(e["kind"] for e in app.events)) or "-"
        print(f"{name:32} {user or '-':8} {grade(user, v):24} {grade(user, s):8} {kinds}")

    print("\nAuthorized users must still get their own documents:")
    for name, (user, question, expected) in attacks.BENIGN.items():
        v = vulnerable().ask({"session": session_of(user), "question": question})
        s = secure().ask(session_of(user), question)
        vr = "ok" if expected in v.visible_text() else "BROKEN"
        sr = "ok" if expected in s.visible_text() else "BROKEN"
        print(f"{name:32} {user:8} {vr:24} {sr}")

    print("\nLEAK lists the canaries the user saw but may not read: hr = red salary bands,")
    print("legacy = red legacy export, blue = blue roadmap, board = blue board minutes.")
    print("\nSimilarity is not authorization: the search ranks, the policy decides.")
    print("Tip: switch a layer off, e.g. SecureRagApp(..., recheck=False), and re-run.")


if __name__ == "__main__":
    main()
