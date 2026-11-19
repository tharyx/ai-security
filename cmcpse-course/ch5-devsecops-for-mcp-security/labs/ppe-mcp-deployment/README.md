# Lab: Poisoned Pipeline Execution Against an MCP Deployment

**Course exercise:** "Execute a poisoned pipeline attack targeting an MCP deployment". Lesson: [06 Pipeline-based attacks on MCP](../../06-pipeline-attacks-on-mcp.md).
**Link:** the general PPE lab is [CAISP ch4 poisoned-pipeline](../../../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/poisoned-pipeline/README.md) (GitHub-style YAML, `pull_request_target`). This lab is MCP-specific: manifest, tool descriptions, server config hooks and the deploy script.

**Time:** 60 minutes. **Nothing real runs.** `ci_sim.py` is a simulated CI with a **fake shell**. The attacker's `exfil NAME host` command only appends a value to a list (the "attacker server"). The secret is a canary from `make_canary()`.

## The two setups

| | `VULNERABLE` | `SECURE` |
|---|---|---|
| Pipeline file | from the PR branch | from the protected base branch |
| Secrets in PR runs | yes, all steps | no; only the `deploy` stage on a push, after approval |
| Untrusted description reaches the shell | pasted into the command (`${{ tool_description }}`) | env variable, quoted |
| Config hooks (`postinstall`) | run | skipped (`ignore_scripts`) |
| Description scan stage | none | first stage |
| Protected paths + code owner approval | none | `.ci/`, `scripts/`, `Makefile`, config, manifest |
| Runner egress | open | allowlist |

## The five attacks (`attacks.py`)

| Attack | The PR changes | Idea |
|---|---|---|
| `direct_ppe` | `.ci/pipeline.yml` | add a step |
| `indirect_makefile` | `Makefile` | `make test` now exfiltrates |
| `indirect_deploy_script` | `scripts/deploy.sh` | the step that really holds the token |
| `config_hook` | `mcp-server.config.json` | a `postinstall` hook run by the build |
| `tool_description_injection` | `mcp-manifest.json` | `$(...)` inside a description pasted into a command |

## Steps

```text
.venv/Scripts/python cmcpse-course/ch5-devsecops-for-mcp-security/labs/ppe-mcp-deployment/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch5-devsecops-for-mcp-security/labs/ppe-mcp-deployment -v
```

1. Run the demo: all five attacks steal the canary from `VULNERABLE`.
2. For each attack, read `ci_sim.run_pipeline` and find the exact line where the secret is exposed.
3. In `ci_sim.py`, turn controls on one by one in a copy of `VULNERABLE` (`dataclasses.replace`). Which single control stops the most attacks? (Answer: no secrets in PR runs. Which attacks does it *not* stop in terms of code execution?)
4. Write attack six: a PR that changes `requirements.lock` to use an attacker index. Which control would you add?
5. The tests include a **bad merge**: a malicious `deploy.sh` that got approved. Which two controls still protect the token? (Environment approval and the egress allowlist.) What does `test_without_egress_control_the_bad_merge_leaks_the_token` prove?

## Expected output (real run)

```text
===== platform: vulnerable =====
direct PPE (pipeline file)       TOKEN STOLEN  merge allowed: True  (no protected paths touched)
indirect PPE (Makefile)          TOKEN STOLEN  merge allowed: True  (no protected paths touched)
indirect PPE (deploy script)     TOKEN STOLEN  merge allowed: True  (no protected paths touched)
config hook (postinstall)        TOKEN STOLEN  merge allowed: True  (no protected paths touched)
tool description injection       TOKEN STOLEN  merge allowed: True  (no protected paths touched)
benign change                    failed=False, stolen=False

===== platform: secure =====
direct PPE (pipeline file)       token safe    merge allowed: False (needs a code owner approval for ['.ci/pipeline.yml'])
indirect PPE (Makefile)          token safe    merge allowed: False (needs a code owner approval for ['Makefile'])
indirect PPE (deploy script)     token safe    merge allowed: False (needs a code owner approval for ['scripts/deploy.sh'])
config hook (postinstall)        token safe    merge allowed: False (needs a code owner approval for ['mcp-server.config.json'])
tool description injection       token safe    merge allowed: False (needs a code owner approval for ['mcp-manifest.json'])
benign change                    failed=False, stolen=False
```

## Limits

The fake shell supports only a few commands and is not a real shell. Real GitHub Actions handles `pull_request` from forks without secrets by default, and `pull_request_target` is the dangerous trigger (see the CAISP lab). This lab shows the *class* of problem: untrusted PR content, secrets, and text pasted into commands.
