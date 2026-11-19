# Lab: Vetting a Marketplace Skill Before Installation

**Course exercise:** "Vetting a Marketplace Skill Before Installation". Lessons: [02 section 2](../../02-attacking-coding-agents.md#2-supply-chain-injection-through-packages-or-marketplace-skills), [03 ClawHavoc](../../03-openclaw-case-study.md), [05](../../05-defending-computer-use-and-coding-agents.md). Background: [CAISP ch6 vetting](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/02-vetting-software-frameworks.md), [CMCPSE backdoored package lab](../../../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/backdoor-mcp-package/README.md).

**Time:** 45 minutes. **Safety:** the vetter only **reads** files. The "malicious" sample is harmless text that copies the *shape* of the ClawHavoc pattern reported in early 2026 (a fake "prerequisite" setup step, a hidden blob, an unknown endpoint, credential paths). Its scripts are never executed. Domains are `.example`.

## Two samples

| Skill | What it is |
|---|---|
| `fixtures/notes-helper` | benign: no network, no install step, signed by a trusted (FAKE) publisher key, hashes match |
| `fixtures/githuub-helper` | malicious-style: name one letter off `github-helper`, publisher account 7 days old, declared hash does not match the shipped `setup.sh`, unsigned, install step, base64 blob and `exec`, unknown endpoints, references to `.ssh` and wallet files |

## The checks (`vet.py`)

| Check | Severity | What it looks for |
|---|---|---|
| install-script | medium | `setup.sh`, `install.ps1`, a declared `install` step |
| obfuscation | high | long base64 blobs, `eval`/`exec`, `base64 -d`, `b64decode` |
| endpoint | high | any URL host not on the allowlist |
| credential-path | critical | `.ssh`, `.aws`, keychains, `wallet.dat`, `Login Data`, `.env` in code |
| typosquat | high | name within 2 edits of a known skill but not equal |
| publisher-age | medium | publisher account younger than 30 days |
| hash | critical / high | file differs from the declared sha256, or is not listed |
| signature | high / critical | unsigned, untrusted publisher key, or signature does not verify |

Verdict: **BLOCK** if any critical or two or more highs, **REVIEW** if anything else, **ALLOW** if clean. The lab signs with an HMAC and a fake shared key only so it runs offline; real systems use asymmetric signatures (for example Sigstore or minisign).

## Steps

```text
.venv/Scripts/python caase-course/ch4-computer-use-browser-and-coding-agents/labs/skill-vetting/demo.py
.venv/Scripts/python -m pytest caase-course/ch4-computer-use-browser-and-coding-agents/labs/skill-vetting -v
```

1. Run the demo and read the finding list for the malicious sample.
2. Make a copy of the benign skill and add one install script. The verdict should become REVIEW (see the test).
3. Rename the malicious skill to something far from every known name. Which check disappears? (Typosquat. The rest still block it.)
4. Think about evasion: split the URL string, or encode it differently. Which check still catches it? (Obfuscation, plus sandbox and egress control at runtime.) A static vetter lowers risk; it never replaces sandboxing.

## Expected output (real run)

```text
== notes-helper: ALLOW ==
  no findings
== githuub-helper: BLOCK ==
  [high    ] typosquat        name 'githuub-helper' is 1 edit(s) from known skill 'github-helper'
  [medium  ] publisher-age    publisher account is only 7 days old
  [critical] hash             scripts/setup.sh does not match the declared sha256
  [high    ] signature        package is unsigned
  [medium  ] install-script   manifest declares an install step: scripts/setup.sh
  [high    ] obfuscation      scripts/helper.py: encoded blob or dynamic execution
  [high    ] endpoint         scripts/helper.py: network endpoint collector.attacker.example
  [critical] credential-path  scripts/helper.py: references '.ssh'
  [medium  ] install-script   scripts/setup.sh looks like an install/setup script
  [high    ] obfuscation      scripts/setup.sh: encoded blob or dynamic execution
  [high    ] endpoint         scripts/setup.sh: network endpoint cdn-updates.attacker.example
```
