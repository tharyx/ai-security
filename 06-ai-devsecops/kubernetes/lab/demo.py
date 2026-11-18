"""Scorecard: every Kubernetes rule against the vulnerable and the secure manifests.

From the repository root:
    python 06-ai-devsecops/kubernetes/lab/demo.py
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import k8s_policy as kp

LAB = Path(__file__).parent


def main() -> None:
    vuln = Counter(f.rule_id for f in kp.check(kp.load_docs(LAB / "vulnerable" / "model-server.yaml")))
    sec = Counter(f.rule_id for f in kp.check(kp.load_docs(LAB / "secure" / "model-server.yaml",
                                                           LAB / "secure" / "admission-policy.yaml")))
    print(f"{'rule':8} {'sev':8} {'title':54} {'vulnerable':11} secure")
    print("-" * 90)
    for rule_id, (severity, title, _) in sorted(kp.RULES.items()):
        v = f"FAIL x{vuln[rule_id]}" if vuln[rule_id] else "ok"
        s = f"FAIL x{sec[rule_id]}" if sec[rule_id] else "ok"
        print(f"{rule_id:8} {severity:8} {title[:54]:54} {v:11} {s}")
    print(f"\nvulnerable: {sum(vuln.values())} findings    secure: {sum(sec.values())} findings")
    print("Tip: delete the default-deny-all NetworkPolicy from secure/model-server.yaml and re-run.")


if __name__ == "__main__":
    main()
