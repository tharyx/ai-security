"""Demo: scan the vulnerable and the fixed MCP server with the MCP SAST and the secret scanner."""

import importlib.util
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sast = load("mcp_sast")

for target in ("vulnerable_server", "fixed_server"):
    findings = sast.scan_tree(HERE / target)
    print(f"\n=== {target}: {len(findings)} finding(s) ===")
    for finding in findings:
        print(" ", finding)
    print("  by rule:", dict(sorted(Counter(f.rule for f in findings).items())))
