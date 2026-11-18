"""Incident drill: what the defenders see when the indirect-injection attack happens.

From the repository root:
    python 10-capstone-project/lab/drill.py

It replays a short, hypothetical incident against the secure assistant with spotlighting
OFF (to act like a real model that follows a paraphrased injection), then walks through
detect -> triage -> contain -> recover -> evidence, printing the audit trail at each step.
"""

from __future__ import annotations

import seed_data as seed
from ops_assistant import IdentityProvider, SecureOpsAssistant

IDP = IdentityProvider(seed.SIGNING_KEY)
ALICE = seed.USERS["alice"]
QUESTION = "Why do we see payments errors? Check the wiki notes."


def show(entries: list[dict]) -> None:
    skip = {"seq", "kind", "cid", "prev", "hash"}
    for e in entries:
        details = ", ".join(f"{k}={v}" for k, v in e.items() if k not in skip)
        print(f"   #{e['seq']:<2} {e['kind']:18} {details}")


def main() -> None:
    app = SecureOpsAssistant(IDP, seed.DOCUMENTS, seed.SERVICES, seed.METRICS, spotlight=False)
    token = IDP.issue(ALICE["sub"], ALICE["tenant"], ALICE["roles"], ALICE["groups"])

    print("T+0   An employee edits wiki page a-wiki-payments and plants a rollback instruction.")
    print("T+1   Alice (operator) asks a normal question that retrieves that page.")
    res = app.handle(token, QUESTION)
    print(f"      assistant -> status={res.status}  answer={res.answer!r}")

    print("\nT+2   DETECT: the SIEM rule 'tool_denied AND possible_injection in one request' fires.")
    alerts = [e for e in app.audit.entries if e["kind"] in ("tool_denied", "possible_injection")]
    show(alerts)

    print(f"\nT+3   TRIAGE: pull every event for correlation id {res.correlation_id}.")
    show([e for e in app.audit.entries if e["cid"] == res.correlation_id])
    source = next(e for e in app.audit.entries if e["kind"] == "possible_injection")["doc"]
    print(f"      root cause: untrusted document {source} reached the model context")

    print("\nT+4   CONTAIN: engage the kill switch while we clean up. Tool calls now fail closed.")
    app.kill_switch.engage()
    check = app.handle(token, 'Is checkout healthy? CALL_TOOL get_service_metrics {"service": "checkout"}')
    print(f"      read-only tool while contained -> status={check.status}  answer={check.answer!r}")

    print(f"\nT+5   RECOVER: quarantine {source}, re-index, release the kill switch, replay the attack.")
    app.retriever.documents = [d for d in app.retriever.documents if d["id"] != source]
    app.kill_switch.release()
    replay = app.handle(token, QUESTION)
    print(f"      replay -> status={replay.status}  retrieved={replay.retrieved}  executed={replay.executed}")
    others = [d for d in replay.retrieved if d.startswith("a-wiki")]
    if others:
        print(f"      FINDING: the replay pulled ANOTHER community page with a planted call ({', '.join(others)}).")
        print("      Policy allowed it (read-only, own tenant), but the fix must cover every community page,")
        print("      not only the page named in the alert.")

    print("\nT+6   EVIDENCE for the post-incident review:")
    print(f"      audit entries: {len(app.audit.entries)}   hash chain intact: {app.audit.verify()}")
    print(f"      change requests created during the incident: {len(app.broker.change_requests)}")
    print("      follow-ups: add the payload to attacks.py, alert on wiki edits that contain CALL_TOOL,")
    print("      and record the residual risk (community content is still retrievable) in the risk register.")


if __name__ == "__main__":
    main()
