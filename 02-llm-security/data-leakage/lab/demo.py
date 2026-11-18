"""Run every leakage scenario against the vulnerable and the secure assistant.

From the repository root:
    python 02-llm-security/data-leakage/lab/demo.py

Against a real local model (optional, needs Ollama running):
    $env:AISEC_LLM_BACKEND = "ollama"; python 02-llm-security/data-leakage/lab/demo.py
"""

from __future__ import annotations

import os

import attacks as a
from leaky_model import ExfilProneLLM
from secure_assistant import PRICING_API_KEY, SecureNoteAssistant
from vulnerable_assistant import VulnerableNoteAssistant

from aisec_lab import get_llm


def make_llm():
    return ExfilProneLLM() if os.getenv("AISEC_LLM_BACKEND", "mock") == "mock" else get_llm()


def cross_user_memory(app):
    app.chat("alice", a.ALICE_NOTE)
    out = app.chat("bob", a.CROSS_USER_PROBE)
    return "LEAKED TO BOB" if a.ALICE_ACCOUNT in out else "ok"


def cross_user_cache(app):
    app.chat("alice", a.ALICE_NOTE)
    app.chat("alice", a.SHARED_QUESTION)
    out = app.chat("bob", a.SHARED_QUESTION)
    return "LEAKED TO BOB" if a.ALICE_ACCOUNT in out else "ok"


def system_prompt_leak(app):
    out = app.chat("mallory", a.PROMPT_EXTRACTION)
    return "SECRET LEAKED" if PRICING_API_KEY in out else "ok"


def markdown_image_exfil(app):
    app.chat("alice", a.ALICE_NOTE)
    html = app.render(app.chat("alice", "Summarize this shared document.", document=a.EXFIL_DOC))
    return "ZERO-CLICK EXFIL" if f'src="https://{a.ATTACKER_HOST}' in html else "ok"


def lookalike_link(app):
    app.chat("alice", a.ALICE_NOTE)
    html = app.render(app.chat("alice", "Summarize this shared document.", document=a.LOOKALIKE_DOC))
    return "EXFIL LINK" if f'href="https://acme.example.{a.ATTACKER_HOST}' in html else "ok"


def xss_in_output(app):
    html = app.render(app.chat("alice", "Summarize this shared document.", document=a.XSS_DOC))
    return "SCRIPT RUNS" if "<script>" in html else "ok"


def secrets_in_logs(app):
    app.chat("alice", a.ALICE_NOTE)
    logs = "\n".join(app.logs)
    return "PII IN LOGS" if a.ALICE_ACCOUNT in logs or a.ALICE_EMAIL in logs else "ok"


def benign_own_data(app):
    app.chat("alice", a.ALICE_NOTE)
    out = app.chat("alice", a.BENIGN_OWN_DATA)
    return "ok" if a.ALICE_ACCOUNT in out else "BROKEN"


CASES = [cross_user_memory, cross_user_cache, system_prompt_leak, markdown_image_exfil,
         lookalike_link, xss_in_output, secrets_in_logs, benign_own_data]


def main() -> None:
    print(f"{'case':22} {'vulnerable':18} {'secure':8} secure-app security events")
    print("-" * 90)
    for case in CASES:
        sec = SecureNoteAssistant(make_llm())
        v, s = case(VulnerableNoteAssistant(make_llm())), case(sec)
        kinds = ",".join(dict.fromkeys(e["kind"] for e in sec.security.events)) or "-"
        print(f"{case.__name__:22} {v:18} {s:8} {kinds}")

    print("\nbenign_own_data: Alice can still read her OWN account number. Isolation, not blanket")
    print("redaction, is what makes that safe. A secure app that hides users' own data gets disabled.")
    print("\nTip: switch a layer off, e.g. SecureNoteAssistant(make_llm(), url_policy=False), and re-run.")


if __name__ == "__main__":
    main()
