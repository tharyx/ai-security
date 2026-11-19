import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import registry_sim as rs

for r in ["nginx", "myuser/app:2.1", "localhost:5000/team/api:dev", "ghcr.io/org/tool@sha256:" + "ab" * 32]:
    print(f"{r:<45} -> {rs.parse_ref(r)}"[:120])

reg = rs.Registry()
d1 = reg.push_image("shop/web", "1.0", {"user": "app"}, [b"layer-os", b"layer-app-v1"])
reg.tag("shop/web", "1.0", "latest")
print("\npush shop/web:1.0 and tag latest ->", d1[:19], "| tags:", reg.list_tags("shop/web"))

d2 = reg.push_image("shop/web", "1.0", {"user": "app"}, [b"layer-os", b"layer-app-v1", b"layer-BACKDOOR-canary"])
print("someone re-pushes tag 1.0 with an extra layer ->", d2[:19])
print("pull by TAG    resolves to:", reg.pull("registry.example/shop/web:1.0")["digest"][:19], "(moved!)")
print("pull by DIGEST resolves to:", reg.pull(f"shop/web@{d1}")["digest"][:19], "(the original, immutable)")
print("untagged but still pullable by digest:", [d[:19] for d in reg.untagged("shop/web")])
print("\nregistry log:")
for line in reg.log:
    print("  " + line)
