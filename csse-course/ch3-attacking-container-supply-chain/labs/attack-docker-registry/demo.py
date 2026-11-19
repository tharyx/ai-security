"""Open registry versus hardened registry. From repo root:
    .venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/attack-docker-registry/demo.py
"""
import attacker as atk
import registry as rg


def seed(reg):
    reg.put_image("shop/api", "1.0", rg.sample_manifest("1.0", secret_env="DB_PASSWORD=FAKE-not-real"))
    reg.put_image("shop/web", "2.3", rg.sample_manifest("2.3"))
    return reg


print("== OPEN registry (no auth, http, mutable tags) ==")
open_reg = seed(rg.Registry())
info = atk.enumerate_registry(open_reg)
print("catalog status :", info["status"], "| repos:", info["repos"])
print("secrets found  :", info["secrets"])
before = open_reg.tags["shop/api"]["1.0"][:19]
print("poison tag     :", atk.poison_tag(open_reg, "shop/api", "1.0").status, "(201 = accepted)")
print("digest changed :", before, "->", open_reg.tags["shop/api"]["1.0"][:19])

print("== HARDENED registry (token auth, TLS only, immutable tags) ==")
tokens = {"ci-push": ["repository:shop/*:pull,push"], "reader": ["repository:shop/*:pull"]}
hard = seed(rg.Registry(auth=True, require_tls=True, immutable_tags=True, tokens=tokens))
print("anonymous catalog     :", atk.enumerate_registry(hard, scheme="https")["status"])
print("plain http with token :", hard.handle("GET", "/v2/shop/api/tags/list", headers={"Authorization": "Bearer reader"}).status)
print("reader pushes         :", hard.handle("PUT", "/v2/shop/api/manifests/9.9", headers={"Authorization": "Bearer reader"},
                                              body=rg.sample_manifest("9.9"), scheme="https").status)
print("ci overwrites 1.0     :", atk.poison_tag(hard, "shop/api", "1.0", headers={"Authorization": "Bearer ci-push"}, scheme="https").status, "(409 = immutable tag)")
print("ci pushes new tag 1.1 :", hard.handle("PUT", "/v2/shop/api/manifests/1.1", headers={"Authorization": "Bearer ci-push"},
                                              body=rg.sample_manifest("1.1"), scheme="https").status)
print("audit log             :", hard.audit)
