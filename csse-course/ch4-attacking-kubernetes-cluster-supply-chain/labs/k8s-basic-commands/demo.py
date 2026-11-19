"""kubectl-style queries on a YAML file. From repo root:
    .venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/k8s-basic-commands/demo.py
"""
from pathlib import Path

import manifest_tools as mt

docs = mt.load_all((Path(__file__).parent / "fixtures/app.yaml").read_text())
print("kubectl get deployments -n shop")
for ns, name, extra in mt.get_table(docs, "deployment", "shop"):
    print(f"  {ns:6} {name:6} {extra}")
print("images:")
for who, image in mt.images(docs):
    print(f"  {who:18} {image}")
print("jsonpath spec.template.spec.containers[0].image ->", mt.jsonpath(docs[1], "spec.template.spec.containers[0].image"))
print("containers without cpu+memory limits:", mt.missing_limits(docs))
print(mt.describe(docs[1]))
