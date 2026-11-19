"""Lint, harden, re-assess, validate profiles. From repo root:
    .venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/minimize-misconfigurations/demo.py
"""
from pathlib import Path

import hardener as h
import profiles as pr

HERE = Path(__file__).parent
df = (h.REPO / "06-ai-devsecops/docker/lab/vulnerable/Dockerfile").read_text()
print("== lint of 06's vulnerable Dockerfile (rule, severity, line, fix) ==")
for rid, sev, line, _msg, fix in h.lint_with_fixes(df)[:6]:
    print(f"  {rid} {sev:8} line {line:2} -> {fix}")

prof = h.RunProfile(image="shop-api@sha256:" + "d" * 64, port=8080, writable_dirs=["/tmp"], caps=["NET_BIND_SERVICE"])
cmd = h.harden_run(prof)
print("== generated run command ==")
print(" ", cmd)
print("  re-assessed:", h.run_assess.verdict(h.assess_text(cmd)))
print("== profiles ==")
print("  seccomp problems :", pr.validate_seccomp(pr.load_seccomp(HERE / "profiles/seccomp-web-app.json")))
print("  apparmor problems:", pr.validate_apparmor((HERE / "profiles/apparmor-web-app").read_text()))
