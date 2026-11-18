"""Run the response attacks against the vulnerable and the secure responder and print a
scorecard graded by impact: attacker URLs in the rendered answer, sensitive values on screen
or hidden inside a URL, and citations that lend false authority.

From the repository root:
    python 03-rag-security/response-security/lab/demo.py
"""

from __future__ import annotations

import os

import attacks
from secure_responder import SecureResponder
from vulnerable_responder import VulnerableResponder


def llm():
    # The mock needs the exfil-prone subclass; a real backend is used as-is.
    return attacks.ExfilProneLLM() if os.getenv("AISEC_LLM_BACKEND", "mock").lower() == "mock" else None


def grade(response) -> str:
    problems = []
    urls = attacks.attacker_urls(response.rendered)
    if urls:
        problems.append(f"EXFIL URL x{len(urls)}")
    leaked = attacks.leaked_values(response.rendered)
    if leaked:
        problems.append("SHOWN: " + ",".join(leaked))
    if attacks.laundered_citation(response):
        problems.append("FAKE CITATION")
    return "; ".join(problems) or "ok"


def main() -> None:
    print(f"{'case':22} {'vulnerable':50} {'secure':7} gate events")
    print("-" * 115)
    for name, question in attacks.ATTACKS.items():
        v = VulnerableResponder(attacks.DOCS, llm()).ask(question)
        app = SecureResponder(attacks.DOCS, llm())
        s = app.ask(question)
        events = ",".join(dict.fromkeys(e["kind"] for e in app.events)) or "-"
        print(f"{name:22} {grade(v):50} {grade(s):7} {events}")

    for name, (question, expected) in attacks.BENIGN.items():
        s = SecureResponder(attacks.DOCS, llm()).ask(question)
        ok = "ok (allowlisted link kept)" if expected in s.rendered else "BROKEN"
        print(f"{name:22} {'-':50} {ok}")

    print("\nThe model proposes an answer; the response gate decides what the user may see.")
    print("Tip: switch a layer off, e.g. SecureResponder(..., url_policy=False), and re-run.")


if __name__ == "__main__":
    main()
