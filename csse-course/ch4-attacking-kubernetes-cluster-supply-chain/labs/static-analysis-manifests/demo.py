"""Static analysis of manifests, a Helm chart and admission webhooks. From repo root:
    .venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/static-analysis-manifests/demo.py
"""
from collections import Counter
from pathlib import Path

import static_check as sc
import webhook_audit as wa

FIX = Path(__file__).parent / "fixtures"
f = sc.check_manifests(FIX / "manifests/bad-deployment.yaml")
print("== manifest checker (module 06) ==", dict(Counter(x.severity for x in f)))
for x in [y for y in f if y.severity in ("CRITICAL", "HIGH")][:5]:
    print(f"  [{x.severity:8}] {x.rule_id} {x.where}: {x.message}")

print("== Helm chart, default values ==")
default = sc.analyse_chart(FIX / "chart")
print(" ", dict(Counter(x.severity for x in default)))
for x in [y for y in default if y.rule_id.startswith("HELM")]:
    print(f"  [{x.severity:8}] {x.rule_id} {x.where}: {x.message}")
secure = sc.analyse_chart(FIX / "chart", sc.yaml.safe_load((FIX / "chart/values-secure.yaml").read_text()))
print("== Helm chart, values-secure.yaml ==")
print(" ", dict(Counter(x.severity for x in secure)), "(chart-level supply chain findings remain: unsigned, unlocked, http repo)")

print("== admission webhooks ==")
docs = wa.load((FIX / "webhooks.yaml").read_text())
for x in wa.audit(docs):
    print(f"  [{x.severity:8}] {x.rule_id} {x.where}: {x.message[:90]}")
weak = docs[0]["webhooks"][0]
print("pod in exempt namespace :", wa.admits(weak, {"policy-exempt": "true"}, webhook_down=False))
print("webhook outage          :", wa.admits(weak, {}, webhook_down=True))
print("same outage, Fail policy:", wa.admits({**weak, "failurePolicy": "Fail"}, {}, webhook_down=True))
