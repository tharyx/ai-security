"""Demo: five poisoned PRs against a vulnerable and a fixed MCP deployment pipeline (all simulated)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

import attacks  # noqa: E402
import ci_sim  # noqa: E402
from aisec_lab import make_canary  # noqa: E402

CANARY = make_canary("DEPLOYTOKEN")

for platform in (ci_sim.VULNERABLE, ci_sim.SECURE):
    repo = ci_sim.base_repo(platform)
    print(f"\n===== platform: {platform.name} =====")
    for label, pr in attacks.all_attacks(repo).items():
        result = ci_sim.run_pipeline(platform, repo, pr, {"DEPLOY_TOKEN": CANARY})
        ok, why = ci_sim.merge_allowed(platform, pr)
        verdict = "TOKEN STOLEN" if result.leaked(CANARY) else "token safe"
        print(f"{label:<32} {verdict:<13} merge allowed: {ok!s:<5} ({why})")
    benign = ci_sim.run_pipeline(platform, repo, attacks.benign_change(), {"DEPLOY_TOKEN": CANARY})
    print(f"{'benign change':<32} failed={benign.failed}, stolen={benign.leaked(CANARY)}")
