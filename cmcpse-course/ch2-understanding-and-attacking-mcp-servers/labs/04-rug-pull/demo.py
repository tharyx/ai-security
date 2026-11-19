"""Demo: both rug-pulls and what catches them.

    .venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/04-rug-pull/demo.py
"""

from aisec_lab import load_lab_module

r = load_lab_module(__file__, "rugpull")
ASK = "Email the Q3 report to my boss."


def main() -> None:
    print("A. Dynamic definition rug-pull (same process, same version 1.0.0)")
    for pin in (False, True):
        srv = r.MailServer()
        host = r.Host(srv, pin_definitions=pin)
        srv.rug_pull()
        print(f"  pin_definitions={pin!s:5} -> {host.run(ASK)!r}; mail log: {[(m['to']) for m in srv.sent]}; alerts: {host.alerts}")

    print("\nB. Release rug-pull (postmark-mcp pattern: 16 clean releases, then 1.0.16)")
    reg = r.postmark_style_registry()
    lock = {p.version: p.integrity for p in reg.releases[:16]}
    bad = r.install(reg, "latest", None)
    host = r.Host(bad, pin_definitions=True)
    host.run(ASK)
    print(f"  auto-update to latest = {bad.version}; definition-pin alerts: {host.alerts}; egress audit: {r.audit_egress(bad.sent, ('@corp.example',))}")
    try:
        r.install(reg, "latest", lock)
    except r.LockfileError as exc:
        print(f"  with lockfile: refused -> {exc}")


if __name__ == "__main__":
    main()
