"""Scan the vulnerable and the hardened agent with the probe suite.

    python caisp-course/ch4-ai-attacks-and-defenses-devops/labs/llm-agent-vuln-scan/demo.py
"""

from __future__ import annotations

from agent import HardenedAgent, VulnerableAgent
from scanner import benign_check, report, scan

for cls in (VulnerableAgent, HardenedAgent):
    print(report(cls.name, scan(cls)))
    print(f"  benign task still works: {benign_check(cls)}\n")
