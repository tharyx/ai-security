"""Demo: lateral movement across three servers sharing one agent context.

    .venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/05-cross-server-privesc/demo.py
"""

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "privesc")


def main() -> None:
    for label, policy in (("VULNERABLE (flat trust)", False), ("DEFENDED (no read-up / no write-down)", True)):
        s = p.build_servers()
        h = p.Host(s, flow_policy=policy)
        h.run(("fetch_page", {"url": "https://blog.example/post"}))
        print(f"== {label}")
        print("   hops:", " -> ".join(f"{t['server']}.{t['tool']}" for t in h.trace))
        print("   canary reached the public ticket:", p.CANARY in s["tickets"].store[p.EXFIL_BOARD])
        print("   blocked:", h.blocked)
        print("   escalation alerts:", p.detect_escalation(h.trace))


if __name__ == "__main__":
    main()
