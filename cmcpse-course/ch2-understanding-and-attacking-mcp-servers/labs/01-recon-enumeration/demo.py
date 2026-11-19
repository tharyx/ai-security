"""Demo: recon of a sloppy fleet and of a hardened fleet.

    .venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/01-recon-enumeration/demo.py
"""

from aisec_lab import load_lab_module

fleet = load_lab_module(__file__, "fleet")
recon = load_lab_module(__file__, "recon")


def main() -> None:
    print("### VULNERABLE FLEET (anonymous scan)")
    print(recon.render_report(recon.scan({a: s.handle for a, s in fleet.vulnerable_fleet().items()})))
    print("\n### HARDENED FLEET (anonymous scan)")
    print(recon.render_report(recon.scan({a: s.handle for a, s in fleet.hardened_fleet().items()})))


if __name__ == "__main__":
    main()
