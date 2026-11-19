"""Demo: the kill chain against the vulnerable server, then the hardened one.

    .venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/08-code-exec-to-compromise/demo.py
"""

from aisec_lab import load_lab_module

c = load_lab_module(__file__, "compromise")


def main() -> None:
    for label, make in (("VULNERABLE vuln-ops (runs as svc)", c.vulnerable_server), ("HARDENED safe-ops (runs as mcp)", c.hardened_server)):
        cloud = c.CloudAPI()
        report = c.attack(make(), cloud)
        print(f"=== {label}")
        for s in report["steps"]:
            print("  ", s)
        print(f"   key stolen: {report['key_stolen']}   cloud compromised: {report['compromised']}\n")


if __name__ == "__main__":
    main()
