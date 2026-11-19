import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import hookrunner as hr  # noqa: E402
import scanners as sc  # noqa: E402

cfg = (HERE / "pre-commit-config.yaml").read_text()
attempts = {
    "clean change": {"app.py": "x = 1\n", "requirements.lock": "examplelib==1.4.2\n"},
    "risky code": {"app.py": "import os\nos.system('ls')\n"},
    "vulnerable deps": {"requirements.lock": "examplelib==1.3.0\nyaml-lite==0.5.0\n"},
}
for label, staged in attempts.items():
    ok, outcomes = hr.commit(staged, cfg, sc)
    print(f"== {label}: commit {'ALLOWED' if ok else 'BLOCKED'} ==")
    for o in outcomes:
        print(f"  {o.hook_id:12} {o.status}")
        for m in o.messages:
            print(f"      {m}")
ok, _ = hr.commit(attempts["risky code"], cfg, sc, no_verify=True)
print(f"== risky code with --no-verify: commit {'ALLOWED' if ok else 'BLOCKED'}; CI recheck exit code = {hr.ci_recheck(attempts['risky code'], cfg, sc)} ==")
