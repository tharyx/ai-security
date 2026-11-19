"""Service-account hygiene and token review. From repo root:
    .venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/service-accounts/demo.py
"""
from pathlib import Path

import yaml

import sa_check as sa

docs = list(yaml.safe_load_all((Path(__file__).parent / "fixtures/sa-and-pods.yaml").read_text()))
print("== manifest findings ==")
for f in sa.analyse(docs):
    print(f"  [{f.severity:6}] {f.rule_id} {f.where}: {f.message}")

NOW = 1_000_100
bound = sa.make_token(sa.bound_claims("shop", "web", "web-1", "uid-1"))
print("== token review ==")
print("claims readable without any key:", sa.decode_claims(bound)["sub"])
for label, token, aud, pods in [
    ("bound, right audience   ", bound, sa.DEFAULT_AUDIENCE, {"uid-1"}),
    ("bound, replayed to Vault", bound, "https://vault.example", {"uid-1"}),
    ("bound, pod deleted      ", bound, sa.DEFAULT_AUDIENCE, set()),
    ("bound, expired          ", sa.make_token(sa.bound_claims("shop", "web", "web-1", "uid-1", now=0, ttl=60)), sa.DEFAULT_AUDIENCE, {"uid-1"}),
    ("legacy secret token     ", sa.make_token(sa.legacy_claims("shop", "legacy-sa")), sa.DEFAULT_AUDIENCE, set()),
]:
    ok, why = sa.token_review(token, audience=aud, now=NOW, live_pod_uids=pods)
    print(f"  {label}: {'OK  ' if ok else 'DENY'} {why}")
