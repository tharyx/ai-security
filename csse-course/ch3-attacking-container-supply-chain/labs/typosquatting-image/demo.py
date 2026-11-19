"""Typosquat detection and policy. From repo root:
    .venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/typosquatting-image/demo.py
"""
from pathlib import Path

import name_sim as ns

policy = ns.Policy.load(Path(__file__).parent / "fixtures/policy.json")
D = "@sha256:" + "f" * 64
for ref in ["nginx", "library/nginx" + D, "nqinx", "ngnix", "ubunut:22.04", "redis-official", "nginx/nginx", "rn1cro/alpine",
            "evil-registry.example/library/nginx" + D, "registry.corp.example/team/api" + D]:
    problems = ns.evaluate(ref, policy)
    print(f"{ref[:44]:44} -> {'OK' if not problems else '; '.join(problems)}")
