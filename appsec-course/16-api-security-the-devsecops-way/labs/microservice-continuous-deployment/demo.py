import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cd  # noqa: E402

key = cd.fake_signing_key()
DEPS = {"gateway": ["orders", "payments"], "orders": [], "payments": []}
old = {s: cd.build_image(f"registry.example/{s}", f"{s} v1") for s in DEPS}
new = {s: cd.build_image(f"registry.example/{s}", f"{s} v2") for s in DEPS}
BROKEN = {new["payments"]}  # payments v2 fails its readiness probe

d = cd.Deployer(key, DEPS, health=lambda s, img: img not in BROKEN,
                error_rate=lambda s, img: 0.08 if (s, img) == ("orders", new["orders"]) else 0.005)


def releases(images, **overrides):
    rels = [cd.Release(s, img, cd.sign(key, img), True) for s, img in images.items()]
    for r in rels:
        for k, v in overrides.get(r.service, {}).items():
            setattr(r, k, v)
    return rels


print("Deploy order:", d.order(list(DEPS)))

staging = cd.Cluster("staging", {s: [old[s]] * 3 for s in DEPS})
print("\n1. Staging, rolling update to v2")
for s, res in d.deploy(staging, releases(new), env="staging").items():
    print(f"   {s:9} {res}")
print("   payments replicas after rollback are all v1:", set(staging.replicas["payments"]) == {old["payments"]})

print("\n2. Production: admission policy")
bad = releases(new, orders={"image": "registry.example/orders:latest"},
               payments={"gates_passed": False})
prod = cd.Cluster("prod", {s: [old[s]] * 4 for s in DEPS})
for s, res in d.deploy(prod, bad, env="prod").items():
    print(f"   {s:9} {res}")

print("\n3. Production canary for orders v2 (staging-approved, but error rate 8%)")
print("   result:", d.deploy(prod, releases({"orders": new["orders"]}), env="prod", strategy="canary"))

print("\nAudit trail:")
for line in d.audit:
    print("  ", line)
