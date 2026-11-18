"""Scorecard: shared admin key (vulnerable) vs per-agent, per-session identity (secure).

From the repository root:
    python 05-agent-security/agent-identity/lab/demo.py
"""

from __future__ import annotations

import attacks
from secure_runtime import PAYROLL_CANARY, FakeClock, SecureAgentRuntime, TokenError
from vulnerable_runtime import SHARED_ADMIN_KEY, VulnerableAgentRuntime

SUMMARIZE = "Summarize this report."


def grade(result: str) -> str:
    if PAYROLL_CANARY in result:
        return "PAYROLL LEAKED"
    if "deleted" in result:
        return "BUCKET DELETED"
    if result.startswith(("401", "403")):
        return "denied"
    return "ok"


def row(name: str, vuln: str, sec: str, note: str) -> None:
    print(f"{name:30} {vuln:16} {sec:16} {note}")


def main() -> None:
    print(f"{'case':30} {'vulnerable':16} {'secure':16} secure-side evidence")
    print("-" * 104)

    # 1. Indirect injection makes a low-risk agent call a destructive action.
    v = VulnerableAgentRuntime()
    s = SecureAgentRuntime()
    sess = s.start_session("alice", "summarizer")
    vr = v.run("summarizer", "alice", SUMMARIZE, attacks.POISONED_REPORT)
    sr = s.run(sess, SUMMARIZE, attacks.POISONED_REPORT)
    row("injected_delete_via_summarizer", grade(vr), grade(sr), sr)

    # 2. Confused deputy: alice borrows the agent's power to read payroll.
    v, s = VulnerableAgentRuntime(), SecureAgentRuntime()
    sess = s.start_session("alice", "summarizer")
    vr = v.run("summarizer", "alice", attacks.CONFUSED_DEPUTY_TASK)
    sr = s.run(sess, attacks.CONFUSED_DEPUTY_TASK)
    row("confused_deputy_payroll", grade(vr), grade(sr), sr)

    # 3. A credential stolen from the summarizer is used for something else, right away.
    v, s = VulnerableAgentRuntime(), SecureAgentRuntime()
    stolen = s.start_session("bob", "summarizer").token  # even bob's summarizer token
    vr = v.cloud.call(SHARED_ADMIN_KEY, *attacks.STOLEN_CALL)
    sr = s.cloud.call(stolen, *attacks.STOLEN_CALL)
    row("stolen_credential_misuse", grade(vr), grade(sr), sr)

    # 4. The same stolen credential, replayed 30 days later.
    clock = FakeClock()
    v, s = VulnerableAgentRuntime(), SecureAgentRuntime(clock=clock)
    stolen = s.start_session("bob", "ticket-bot").token
    clock.advance(attacks.REPLAY_AFTER_SECONDS)
    vr = v.cloud.call(SHARED_ADMIN_KEY, "create_ticket", {"title": "spam"})
    sr = s.cloud.call(stolen, "create_ticket", {"title": "spam"})
    row("replay_after_30_days", "WORKS" if "created" in vr else vr, grade(sr), sr)

    # 5. The attacker edits the token to add a scope.
    s = SecureAgentRuntime()
    token = s.start_session("alice", "summarizer").token
    forged = attacks.tamper_token(token, "storage:admin")
    sr = s.cloud.call(forged, *attacks.STOLEN_CALL)
    row("tampered_token", "n/a (no token)", grade(sr), sr)

    # 6. A planner tries to give a sub-agent more power than it has itself.
    s = SecureAgentRuntime()
    planner = s.start_session("alice", "planner")
    try:
        s.delegate(planner, "ticket-bot", attacks.WIDENING_REQUEST)
        sr, note = "WIDENED", "-"
    except TokenError as exc:
        sr, note = "denied", str(exc)
    row("subagent_scope_widening", "ALREADY ADMIN", sr, note)

    # 7. Kill one session mid-task.
    s = SecureAgentRuntime()
    sess = s.start_session("alice", "ticket-bot")
    s.end_session(sess)
    sr = s.run(sess, 'CALL_TOOL create_ticket {"title": "after revoke"}')
    row("revoked_session_reuse", "CANNOT REVOKE", grade(sr), sr)

    # 8. Who deleted the bucket? Then: can an insider hide it?
    v = VulnerableAgentRuntime()
    v.run("ticket-bot", "bob", 'CALL_TOOL delete_bucket {"bucket": "build-cache"}')
    s = SecureAgentRuntime()
    planner = s.start_session("bob", "planner")
    janitor = s.delegate(planner, "storage-janitor", {"storage:admin"})
    s.run(janitor, 'CALL_TOOL delete_bucket {"bucket": "build-cache"}')
    row("attribution_who_deleted", v.cloud.log[-1].split()[0], "attributed", s.who_did("delete_bucket")[0])
    anchor = s.audit.anchor()
    del v.cloud.log[-1]
    s.audit.entries = [e for e in s.audit.entries if e.get("action") != "delete_bucket"]
    row("insider_deletes_log_entry", "UNDETECTED", "DETECTED", s.audit.verify(anchor))

    # 9. Benign path.
    v, s = VulnerableAgentRuntime(), SecureAgentRuntime()
    vr = v.run("summarizer", "alice", attacks.BENIGN_TASK)
    sr = s.run(s.start_session("alice", "summarizer"), attacks.BENIGN_TASK)
    row("benign_own_report", grade(vr), grade(sr), sr[:40] + "...")

    print("\nThe secure runtime never holds a long-lived secret. Every action carries the human")
    print("AND the agent chain, the resource server re-checks both, and the log can prove it.")
    print("Tip: try SecureAgentRuntime(scoped=False, check_user=False) and re-run case 2.")


if __name__ == "__main__":
    main()
