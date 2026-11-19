import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import portainer_sim as ps

for title, ui in (("fresh install, exposed, no admin yet", ps.vulnerable()), ("default credentials", ps.default_creds()), ("hardened", ps.hardened())):
    print(f"== {title} ==")
    for sev, msg in ui.exposure_findings() or [("OK", "no findings")]:
        print(f"  [{sev:<8}] {msg}")
if True:
    ui = ps.vulnerable()
    print("\nAttacker on the fresh install: takeover ->", ui.first_run_takeover("attacker-chosen-canary"), "| login ->", ui.login("admin", "attacker-chosen-canary"))
    br = ui.blast_radius()
    print("Blast radius:")
    for k, v in br.items():
        print(f"  {k:<32} {v}")
    print("\nSame blast radius on the hardened UI:", ps.hardened().blast_radius()["host_root_equivalent"], "(root-equivalent?)")
print("\nHardening checklist:")
for h in ps.HARDENING[:4]:
    print(" -", h[:100])
