"""Demo: fuzz the vulnerable MCP server, then the fixed one. Nothing real runs (sandboxed)."""

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVERS = HERE.parent / "sast-vulnerable-mcp-server"
spec = importlib.util.spec_from_file_location("fuzzer", HERE / "fuzzer.py")
fuzzer = importlib.util.module_from_spec(spec)
sys.modules["fuzzer"] = fuzzer
spec.loader.exec_module(fuzzer)

for target in ("vulnerable_server", "fixed_server"):
    findings = fuzzer.fuzz(SERVERS / target, iterations=400, seed=1234)
    print(f"\n=== {target}: {len(findings)} finding(s) {fuzzer.summarize(findings)} ===")
    for finding in findings:
        print(" ", finding)
