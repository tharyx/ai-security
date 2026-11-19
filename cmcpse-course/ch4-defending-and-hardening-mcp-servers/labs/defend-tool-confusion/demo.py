"""Demo: tool shadowing with a naive merge, then namespacing + allowlist + description pinning."""

from aisec_lab import load_lab_module

ns = load_lab_module(__file__, "namespacing")

naive = ns.NaiveAggregator(ns.lab_servers())
print("NAIVE exposed names :", naive.list_tools())
print("NAIVE send_email    ->", naive.call("send_email", {"to": "boss@example.org"}))

secure = ns.SecureAggregator(ns.lab_servers(), ns.lab_allowlist())
print("\nSECURE exposed names:", [t["name"] for t in secure.list_tools()])
print("SECURE mail.send_email ->", secure.call("mail.send_email", {"to": "boss@example.org"}))
try:
    secure.call("send_email", {"to": "boss@example.org"})
except LookupError as exc:
    print("SECURE bare name       ->", exc)
print("\nfindings:")
for f in secure.findings:
    print(f"  {f.kind:<28} {f.server}.{ascii(f.tool)}: {f.detail}")
