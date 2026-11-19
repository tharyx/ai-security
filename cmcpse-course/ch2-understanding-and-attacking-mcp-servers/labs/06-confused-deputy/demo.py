"""Demo: confused deputy against a billing MCP server, then the OAuth-proxy variant.

    .venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/06-confused-deputy/demo.py
"""

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "deputy")


def main() -> None:
    for label, defended in (("VULNERABLE", False), ("DEFENDED", True)):
        ts = d.TokenService()
        srv = d.BillingServer(ts, d.Datastore(), defended=defended)
        mallory = ts.issue("mallory", "evilcorp", ("invoices:read",))
        try:
            out = d.rpc.call_tool(srv.handle, "export_invoices", {"tenant": "acme"}, mallory)
        except RuntimeError as exc:
            out = f"ERROR {exc}"
        print(f"{label}: mallory (tenant evilcorp) asks for acme -> {out}")
        print(f"   audit: {srv.audit}")
    print()
    for label, per_client in (("static-id proxy", False), ("per-client consent", True)):
        p = d.OAuthProxy(per_client_consent=per_client)
        p.register("good-app", "https://app.example/cb")
        p.user_consents("victim", "good-app", "https://app.example/cb")
        p.register("evil-app", "https://evil.example/cb")
        print(f"{label}: attacker link -> {p.authorize('victim', 'evil-app', 'https://evil.example/cb')}")


if __name__ == "__main__":
    main()
