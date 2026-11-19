# Lab: Generate an SBOM for an MCP Server and Analyze Its Components

**Course exercise:** "Generate an SBOM for an MCP server and analyze its components". Lessons: [02 vetting (risk scoring)](../../02-vetting-third-party-mcp-servers.md#2-dependency-analysis-and-risk-scoring), [03 transparency (SBOMs)](../../03-transparency-and-integrity.md#2-generating-sboms-for-mcp-servers). General SBOM and ML-BOM lab: [CAISP sbom-and-mlbom](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom/).

**Time:** 45 minutes. Offline. The project is a **fixture**: `fixtures/notes-mcp/lock.json` is a simplified lock file with fictional packages, and `fixtures/advisories.json` holds fictional advisories (`LAB-ADV-...`). Nothing is downloaded.

## Files

| File | Role |
|---|---|
| `fixtures/notes-mcp/lock.json` | The server project: name, transport, tools, and 8 packages (4 direct, 4 transitive) |
| `fixtures/advisories.json`, `fixtures/policy.json` | Local advisory data; policy (denied licenses, allowed registries, acceptable score) |
| `sbom.py` | `generate_sbom`, `validate_sbom`, `analyze_sbom`, `render_report` |
| `notes-mcp.cdx.json` | The SBOM the demo writes (a sample you can open) |
| `demo.py`, `test_cmcpse6_sbom.py` | Demo and tests |

## What the SBOM looks like

A CycloneDX 1.5 shaped JSON document (the structure follows the CycloneDX format; this lab does **not** validate against the official schema, so use `cyclonedx-py`, cdxgen or Syft for real SBOMs and validate with the CycloneDX tooling):

- `metadata.component`: the MCP server itself, with lab **custom properties** for the transport and each tool (these names are lab conventions, not standards).
- `components[]`: each package with `purl` (`pkg:pypi/name@version`), `hashes`, `licenses`, and lab properties for direct/transitive and registry.
- `dependencies[]`: the graph (root to direct to transitive).

## What the analysis checks

| Check | Fixture finding |
|---|---|
| Known vulnerabilities by version range | `yamlish 2.3.0` (fixed in 2.4.1) and `h11-lite 0.14.0` match; `pydantic-lite` does **not** (advisory already fixed in its version) |
| Unpinned component | `tinycrypto` has only a constraint (`>=0.5`) and no hash |
| License policy | `notesdb-client` is AGPL-3.0-only (denied); `pydantic-lite` license unknown |
| Registry allowlist | `internal-metrics` comes from `pypi.attacker-mirror.example` (looks like dependency-confusion exposure) |
| Transitive depth | `notes-mcp -> mcp-sdk-lite -> httpx-lite -> h11-lite` is depth 3 |
| Risk score | transparent points table from lesson 02; the worst component decides the verdict |

## Steps

```text
.venv/Scripts/python cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sbom-mcp-server/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sbom-mcp-server -v
```

1. Open `notes-mcp.cdx.json`. Find `yamlish`'s `purl`, hash and license.
2. Fix the project: upgrade `yamlish` to 2.4.1 in `lock.json`, pin `tinycrypto`, move `internal-metrics` to `pypi.org`, replace `notesdb-client`. Rerun until the verdict is "acceptable". Note that the SBOM `serialNumber` changes when the lock changes.
3. An advisory arrives for `h11-lite`. Using only the SBOM, list every server that is affected (hint: write a loop over several SBOM files).
4. Add a check: fail if a dependency was added since the previous SBOM ("new dependency" review trigger). Compare two SBOMs.
5. Optional, real tools (not executed by the repo author): `pip install cyclonedx-bom` then `cyclonedx-py` on a real project, or `syft <dir> -o cyclonedx-json`; flags change between versions, check the docs.

## Expected output (real run)

```text
valid: ok
serialNumber: urn:uuid:89154635-2e6d-5496-b05d-a7a3deb85f64 | specVersion: 1.5
top component: notes-mcp@1.2.0 ['streamable-http', 'read_note', 'list_notes', 'send_report']
first component: (JSON excerpt omitted here; see notes-mcp.cdx.json)

components: 8 (direct 4, transitive 4, max depth 3)
vulnerable: ['yamlish', 'h11-lite']
unpinned: ['tinycrypto']
denied licenses: ['notesdb-client']  unknown licenses: ['pydantic-lite']
registry not allowed: ['internal-metrics']
risk ranking:
   5  yamlish==2.3.0: LAB-ADV-0001 (high): unsafe load allows code execution (fictional lab advisory)
   4  h11-lite==0.14.0: LAB-ADV-0003 (medium): request smuggling in a rare parser mode (fictional lab advisory); deep transitive dependency (depth 3)
   3  internal-metrics==0.3.1: registry not allowed: pypi.attacker-mirror.example
   3  tinycrypto==?: unpinned (constraint >=0.5)
   2  notesdb-client==1.9.0: denied license AGPL-3.0-only
   1  pydantic-lite==2.7.0: license unknown
verdict: NEEDS REVIEW (worst score 5)

wrote notes-mcp.cdx.json ( 4542 bytes )
```

## Limits

The lock file is a simplified stand-in; real lock files (uv.lock, package-lock.json) need real parsers. Advisories are fictional. Matching by version range is simplified (real tools use ecosystem-specific ranges and the OSV database). An SBOM lists what is *declared*; it does not detect a backdoor in a package version (see the [backdoor lab](../backdoor-mcp-package/README.md)).
