"""Sign, verify, tamper, re-point a tag. From repo root:
    .venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/sign-container-images/demo.py
"""
import sign_verify as sv

KEY = b"demo-key-for-simulation-only"
m1 = {"layers": ["a", "b"], "entrypoint": ["/app"]}
d1 = sv.digest_of(m1)
reg = {"tags": {"shop/api:1.0": d1}, "manifests": {d1: m1}, "sigs": {d1: [sv.sign(d1, "ci@example.invalid", KEY)]}}
trusted, allowed = {"ci@example.invalid": KEY}, {"ci@example.invalid"}
print("1 signed image      :", sv.verify(reg, "shop/api:1.0", trusted, allowed))
m2 = {"layers": ["a", "b", "backdoor"], "entrypoint": ["/app"]}
d2 = sv.digest_of(m2)
reg["manifests"][d2] = m2
reg["tags"]["shop/api:1.0"] = d2
print("2 tag re-pointed    :", sv.verify(reg, "shop/api:1.0", trusted, allowed))
reg["tags"]["shop/api:1.0"] = d1
reg["manifests"][d1] = m2
print("3 manifest tampered :", sv.verify(reg, "shop/api:1.0", trusted, allowed))
reg["manifests"][d1] = m1
print("4 untrusted signer  :", sv.verify(reg, "shop/api:1.0", trusted, {"someone-else"}))
