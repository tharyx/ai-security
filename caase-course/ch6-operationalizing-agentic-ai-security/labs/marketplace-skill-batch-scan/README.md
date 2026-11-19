# Lab: Scanning Marketplace Skills for Supply-Chain Risk (batch scanner)

**Syllabus exercise:** Scanning Marketplace Skills for Supply-Chain Risk · **Lesson:** [04](../../04-vetting-harnesses-models-and-marketplaces.md) · **Offline, 9 tests.** Single-skill version: [chapter 4 skill-vetting](../../../ch4-computer-use-browser-and-coding-agents/labs/skill-vetting). This lab is the at-scale version with scoring and a report.

`batch_scan.py` scans many skills (dicts of file name to text), scores each with weighted rules, assigns a verdict (`allow` under 25, `review` 25 to 59, `block` 60 and above), ranks them, and writes **JSON** and **Markdown** reports with a summary. Everything is harmless text: "exfiltration" is a string pointing at a `.example` domain; nothing is fetched or run.

| Rule | Points | Catches |
|---|---|---|
| `pipe_to_shell` | 60 | download piped into a shell |
| `credential_paths` | 50 | references to SSH keys, cloud credentials, keychains, wallets, `.env` |
| `injection_text` | 45 | instructions aimed at the model |
| `hidden_unicode` | 40 | zero-width and bidi characters |
| `typosquat` | 40 | name 1 to 2 edits from a popular skill |
| `encoded_blob` | 35 | long base64-like strings |
| `excess_permissions` | 30 | shell + network + filesystem without justification |
| `unknown_domain` | 25 | URLs outside the allowlist |
| `unpinned_install` | 10 | install without a version |

This is a triage filter. It can be evaded (obfuscation, split strings, runtime downloads), so a clean result is not proof of safety: sandbox skills and pin them.

## Run

```text
.venv/Scripts/python -m pytest caase-course/ch6-operationalizing-agentic-ai-security/labs/marketplace-skill-batch-scan
.venv/Scripts/python caase-course/ch6-operationalizing-agentic-ai-security/labs/marketplace-skill-batch-scan/demo.py
```

Real output (condensed from the Markdown report; the demo writes `report.md` and `report.json`):

```text
Scanned **301** skills: block=6, review=28, allow=267
Findings by rule: unknown_domain 11, pipe_to_shell 6, credential_paths 6, encoded_blob 6, injection_text 5, hidden_unicode 5, typosquat 1
planted bad: 33 | flagged: 34 | all planted caught: True
```

(34 flagged = the 33 planted skills plus the typosquat added by the demo.) The tests plant bad skills in 200 generated ones and assert the flagged set equals the planted set exactly (no misses, no false positives), and scan 2,000 skills in a few seconds.

## Break it yourself

1. Split a URL or the word `curl` across two lines. Does the scanner still catch it? Write the evasion as a test, then improve the rule.
2. Add a rule for `eval(` or `exec(` in bundled scripts, with a test.
3. Stretch: add a "rug pull" check that compares a skill's file hashes with a pinned lockfile.
