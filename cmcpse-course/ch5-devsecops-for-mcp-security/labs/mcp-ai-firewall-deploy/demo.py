"""Demo: deploy the firewall in monitor mode, then enforce mode, and tune the threshold."""

import copy
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(f"fwdemo_{name}", HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gateway, upstream, tune = load("gateway"), load("upstream"), load("tune")
policy = gateway.load_policy(HERE / "firewall.yaml")


def call(gw, client, tool, **args):
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}}
    response = gw.handle(client, request)
    shown = response["result"]["content"][0]["text"] if "result" in response else f"ERROR {response['error']['message']}"
    print(f"  {tool}({args}) -> {shown[:80]}")


for mode in ("monitor", "enforce"):
    pol = copy.deepcopy(policy)
    pol["mode"] = mode
    gw = gateway.Gateway(pol, upstream, clock=iter(range(1000)).__next__)
    print(f"\n=== mode: {mode} ===")
    call(gw, "alice", "read_note", name="welcome")
    call(gw, "alice", "read_note", name="meeting")
    call(gw, "alice", "read_note", name="config")
    call(gw, "alice", "read_note", name="poisoned")
    call(gw, "alice", "delete_note", name="welcome")
    listed = gw.handle("alice", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    print("  tools/list ->", [t["name"] for t in listed["result"]["tools"]])
    for _ in range(4):
        call(gw, "bob", "read_note", name="welcome")
    print("  audit decisions:", [e["decision"] for e in gw.audit])

print("\n=== tuning the injection threshold on labelled traffic ===")
corpus = tune.load_corpus()
print("threshold  TP FP TN FN")
for row in tune.sweep(policy, corpus):
    print(f"{row['threshold']:>9}  {row['tp']:>2} {row['fp']:>2} {row['tn']:>2} {row['fn']:>2}")
best = tune.recommend(policy, corpus)
print("recommended with 0 false positives:", best["threshold"], "-> recall", best["recall"])
print("still wrong at that threshold:", best["wrong"])
