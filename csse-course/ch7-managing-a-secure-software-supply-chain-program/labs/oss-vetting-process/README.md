# Lab: Establish a vetting process for open-source components

**Course exercise:** "Establish a vetting process for open-source components". Lessons: [02](../../02-vetting-process-and-automation.md). Diagram: [intake workflow](../../../../images/csse-ch7-vetting-intake-workflow.svg). Related: [CAISP package-vetting](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting/) (typosquat, dependency confusion, hashes), [CAISP lesson 02](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/02-vetting-software-frameworks.md), [CMCPSE vetting](../../../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/02-vetting-third-party-mcp-servers.md), [CAASE skill-vetting](../../../../caase-course/ch4-computer-use-browser-and-coding-agents/labs/skill-vetting/README.md).

**Time:** 60 minutes. **Safety:** fixture data only. All package names are fictional (except popular names used as typosquat targets).

## What it builds

An intake engine: **request form (YAML) -> checks -> approve / conditional / reject -> hash-chained audit record.**

| Check | Rule (example policy; set your own) |
|---|---|
| Form | required fields and a valid `component_type` (open_source, commercial, third_party, proprietary) |
| Scorecard-like score | weighted average of check scores; below 4 reject, 4 to 6 conditional |
| License | allow list, review list (needs legal), deny list (AGPL, no license) |
| Vulnerabilities | known-exploited or unfixed critical/high = reject; fixed in a newer version = conditional with the version to use |
| Maintainer health | stale release, bus factor 1, recent ownership change |
| Malicious heuristics (**stub**) | name close to a popular package, network at install, obfuscation, brand-new package. Not proof either way |
| Type checks | commercial: vendor SBOM, PSIRT contact, attestation. Third party: contract clause, SBOM on delivery. Proprietary: review enforced, SAST gate, signed builds |

Decision rule: any `fail` = reject; else any `condition` = conditional (with a list of conditions); else approve. The audit record stores every finding, and each record includes the hash of the previous one, so edits are detectable (`verify_chain`).

## Steps

```text
.venv/Scripts/python csse-course/ch7-managing-a-secure-software-supply-chain-program/labs/oss-vetting-process/demo.py
.venv/Scripts/python -m pytest csse-course/ch7-managing-a-secure-software-supply-chain-program/labs/oss-vetting-process -v
```

1. Read `fixtures/request-template.yaml`, then run the demo and match each outcome to its reasons.
2. `parsekit` 2.3.1 is conditional and 2.3.2 is approved: the decision belongs to a **version**, not a name.
3. `agpl-chart` has a perfect score and is still rejected. Which control is policy rather than risk?
4. Add a rule: reject a package whose scorecard `Dangerous-Workflow` is below 5. Add a test.
5. Tamper with the audit file (see `test_audit_tamper_detected`). Why a hash chain and not just a log?
6. Stretch: replace the fixture lookup with a real Scorecard run (`scorecard --repo=...`) and OSV lookup in your course lab (hedged: [real-tools](../../real-tools/README.md)).

## Expected output (real run, trimmed)

```text
acme-http         3.2.1  approve     score=9.4
yamlish           0.9.0  conditional score=7.8
    condition license: GPL-3.0 needs legal review before shipping
reqeusts          2.0.0  reject      score=4.0
    fail      malicious_heuristics: name is very close to popular package 'requests' (typosquat?); install script reaches the network; ...
oldcrypto         1.1.0  reject      score=3.2
    fail      vulnerabilities: ADV-FIXTURE-0001 (critical) has no fix
parsekit          2.3.1  conditional score=8.6
    condition vulnerabilities: use a fixed version: 2.3.2 or later
agpl-chart        5.0.0  reject      score=9.6
    fail      license: AGPL-3.0 is denied by policy
exploited-lib     4.0.0  reject      score=8.3
    fail      vulnerabilities: known-exploited: ADV-FIXTURE-0003
vendorsdk         8.1    conditional score=None
    condition commercial:vendor_sbom: vendor SBOM missing: request from vendor
internal-billing  1.7    approve     score=None
audit chain valid: True
```

Tests: 26.
