"""Demo: tool poisoning (description and schema variants) against a vulnerable and a defended host.

    .venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/02-tool-poisoning/demo.py
"""

import tempfile

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "poison")


def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        ws = p.make_workspace(d)
        for kind in ("description", "schema"):
            print(f"=== variant: hidden text in the tool {kind} ===")
            for label, kw in (("VULNERABLE host", {}), ("DEFENDED host (scan + pinned args)", {"scan": True, "baseline": {"add": {"a", "b"}, "read_file": {"path"}}})):
                calc, files = p.calculator_server(ws, kind), p.files_server(ws, confined=False)
                host = p.Host({"calculator": calc, "files": files}, **kw)
                answer = host.run("Please add 2 and 3.")
                print(f"{label}: answer={answer!r}")
                print(f"   canary file read: {bool(files.reads)}   exfiltrated to attacker: {any(ws.canary in e for e in calc.exfil)}")
                if host.blocked_servers:
                    print(f"   blocked servers: {host.blocked_servers}")
        print("\nScanner verdict for the description variant:", p.scan_tool(p.rpc.request(p.calculator_server(ws, 'description').handle, 'tools/list')['result']['tools'][0]))


if __name__ == "__main__":
    main()
