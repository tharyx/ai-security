# Lab: Generating an AI/Agent Bill of Materials (AIBOM) for a Harness

**Syllabus exercise:** Generating an AI/Agent Bill of Materials (AIBOM) for a Harness · **Lesson:** [05](../../05-aibom-provenance-and-signing.md) · **Offline, 7 tests.** Builds on [CAISP sbom-and-mlbom](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom).

`harness/harness.json` describes a fictional support harness: model and provider, two tools, an MCP server, a skill, a prompt, and two libraries. `aibom.py` builds a **CycloneDX 1.6-shaped** JSON document (bomFormat, specVersion, serialNumber, components with `bom-ref`, type, version, hashes, licenses, properties, and a dependency graph), computes SHA-256 hashes of the prompt and skill files, validates structure, and diffs two AIBOMs.

> The validator is structural. For real use, validate against the official CycloneDX JSON schema and check the current spec version at cyclonedx.org.

## Run

```text
.venv/Scripts/python -m pytest caase-course/ch6-operationalizing-agentic-ai-security/labs/aibom-harness
.venv/Scripts/python caase-course/ch6-operationalizing-agentic-ai-security/labs/aibom-harness/demo.py
```

Real output (the demo also writes `aibom.cdx.json`):

```text
serial: urn:uuid:e0b238d5-f505-532c-a0e8-90a45b0b4936
  model       qwen3-4b-instruct    2025-07-01   sha256=aaaaaaaaaaaa
  tool        search_kb            1.0.0        sha256=1a2b938d64d7
  tool        draft_reply          1.0.0        sha256=3404a469d3ed
  mcp-server  tickets-mcp          0.3.2        sha256=bbbbbbbbbbbb
  skill       triage               1.0.0        sha256=f5ea2be313de
  prompt      system               7            sha256=fb3317215884
  library     pydantic             2.9.2        sha256=-
  library     httpx                0.27.2       sha256=-
validation problems: []
after pinning removed: ["search_kb: floating version 'latest' (pin it)"]
```

(The model and MCP hashes are placeholders `aaa...` and `bbb...` in the fixture. In real use, hash the actual files.)

## What the validator checks

Required fields, `latest`/`*`/`^` floating versions, 64-hex SHA-256 hashes, model licence present, duplicate `bom-ref`, dependencies pointing to unknown refs, and that a model component exists. `diff()` reports added, removed and changed components, so a silent prompt edit or model version swap shows up in review.

## Break it yourself

1. Edit `harness/prompts/system.md` and re-run: the prompt hash and serial change.
2. Add an MCP server with `"version": "latest"`. Predict the validator output.
3. Stretch: add dataset components and a `modelCard` block (CycloneDX supports it; check the spec).
