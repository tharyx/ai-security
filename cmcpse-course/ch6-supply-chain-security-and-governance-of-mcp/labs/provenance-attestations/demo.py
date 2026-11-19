"""Demo: create a signed provenance statement for an MCP server build and check it in a deploy gate."""

import copy
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import provenance as p  # noqa: E402

work = Path(tempfile.mkdtemp())
artifact = work / "notes-mcp-1.2.0.tar"
artifact.write_bytes(b"pretend this is the built MCP server archive")
BUILDER = "https://ci.example.internal/builders/mcp-release@v1"
REPO = "https://git.example.internal/acme/notes-mcp"
KEYS = {"lab-attest-1": p.LAB_KEY}
policy = p.Policy({BUILDER}, REPO, {"refs/heads/main"}, {".ci/release.yml"})

statement = p.make_statement(
    {"notes-mcp-1.2.0.tar": artifact}, BUILDER, REPO, "refs/heads/main", "9f2c4e1a7b" * 4,
    ".ci/release.yml", [{"uri": "pkg:pypi/mcp-sdk-lite@1.4.0", "digest": {"sha256": "11" * 32}}], "run-4711",
)
print(json.dumps({k: statement[k] for k in ("_type", "predicateType")}, indent=1))
print("subject:", statement["subject"])
print("builder:", statement["predicate"]["runDetails"]["builder"]["id"])
envelope = p.sign_statement(statement)
print("envelope keys:", list(envelope), "| payloadType:", envelope["payloadType"])

print("\n-- gate: good build:", p.deploy_gate(envelope, {"notes-mcp-1.2.0.tar": artifact}, KEYS, policy))

evil = work / "evil.tar"
evil.write_bytes(b"swapped archive")
print("-- gate: artifact swapped after the build:", p.deploy_gate(envelope, {"notes-mcp-1.2.0.tar": evil}, KEYS, policy).reasons)

fork = copy.deepcopy(statement)
fork["predicate"]["buildDefinition"]["externalParameters"]["repository"] = "https://git.example.internal/mallory/notes-mcp"
print("-- gate: built from a fork:", p.deploy_gate(p.sign_statement(fork), {"notes-mcp-1.2.0.tar": artifact}, KEYS, policy).reasons)

rogue = copy.deepcopy(statement)
rogue["predicate"]["runDetails"]["builder"]["id"] = "https://laptop.example/builder"
print("-- gate: built on an unknown builder:", p.deploy_gate(p.sign_statement(rogue), {"notes-mcp-1.2.0.tar": artifact}, KEYS, policy).reasons)

print("-- gate: forged statement (attacker key):", p.deploy_gate(p.sign_statement(statement, key=b"FAKE-attacker"), {"notes-mcp-1.2.0.tar": artifact}, KEYS, policy).reasons)
