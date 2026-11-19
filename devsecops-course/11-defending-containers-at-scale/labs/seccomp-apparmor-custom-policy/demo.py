"""Generate seccomp + AppArmor policy from fixtures and validate good and bad ones. From repo root:
    .venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/seccomp-apparmor-custom-policy/demo.py
"""
import json
from pathlib import Path

import policy_gen as pg

FIX = Path(__file__).parent / "fixtures"
obs = pg.parse_strace((FIX / "strace_web_app.txt").read_text())
print("observed syscalls:", obs)
prof, refused = pg.gen_seccomp(obs)
print("generated seccomp: default =", prof["defaultAction"], "| allowed =", len(prof["syscalls"][0]["names"]), "| refused =", refused)
print("validate generated:", pg.validate_seccomp(prof) or "OK")
prof2, refused2 = pg.gen_seccomp(pg.parse_strace((FIX / "strace_with_ptrace.txt").read_text()), with_baseline=False)
print("second capture refuses:", refused2)
print("validate bad_seccomp.json:", pg.validate_seccomp(json.loads((FIX / "bad_seccomp.json").read_text())))
aa = pg.gen_apparmor("dso-web-app", pg.parse_accesses((FIX / "file_accesses.txt").read_text()))
print("---- generated AppArmor profile ----")
print(aa)
print("validate generated:", pg.validate_apparmor(aa) or "OK")
print("validate bad_apparmor.profile:")
for p in pg.validate_apparmor((FIX / "bad_apparmor.profile").read_text()):
    print("  -", p)
