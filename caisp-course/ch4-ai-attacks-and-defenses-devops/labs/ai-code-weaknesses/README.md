# Lab: Finding and Fixing Weaknesses in AI Code

**Course exercise:** "Finding and Fixing Weaknesses in AI Code". A small Bandit-style static analysis tool, an intentionally vulnerable AI app, and your fix.

**Time:** 45 minutes. Offline. The vulnerable file is **only parsed, never imported or run**. All keys in it are fake.

## Files

| File | Role |
|---|---|
| `scanner.py` | AST scanner with 8 rules (AIC001 to AIC008) |
| `sample_app/vulnerable_app.py` | The vulnerable app. Do not run it |
| `sample_app/fixed_app.py` | The reference fix |
| `my_fix/app.py` | Your copy. Fix this one |

## Steps

1. Scan the vulnerable app:

```text
.venv/Scripts/python caisp-course/ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses/scanner.py caisp-course/ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses/sample_app/vulnerable_app.py
```

2. For each finding, write one sentence: what could an attacker do? (`pickle.load` on a downloaded model gives code execution. `eval(model_output)` gives code execution for anyone who can influence the prompt.)
3. Fix `my_fix/app.py` until the scanner is clean. Keep the same four functions.
4. Run the tests (the last one is skipped until you edit your file):

```text
.venv/Scripts/python -m pytest caisp-course/ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses -v
```

## What the scanner looks for

| Rule | Weakness | Typical fix |
|---|---|---|
| AIC001 | `pickle.load`, `joblib.load`, `torch.load` without `weights_only=True`, `yaml.load` | safetensors, `weights_only=True`, `yaml.safe_load` |
| AIC002 | Model output flows into `eval`, `exec`, `os.system`, `subprocess` | parse into a schema, run only allowlisted actions |
| AIC003 | `eval`/`exec` with a non-literal argument | remove it |
| AIC004 | `shell=True`, `os.system` | argument list, `shell=False` |
| AIC005 | Hardcoded secret | environment variable or secret manager |
| AIC006 | `trust_remote_code=True` | `False`, or review the code and pin the revision |
| AIC007 | `verify=False` | keep TLS verification on |
| AIC008 | `from_pretrained` without `revision=` | pin a commit hash |

## Expected output (`demo.py`)

```text
== vulnerable_app.py: 13 finding(s) ==
  line 15  AIC005 MEDIUM   hardcoded secret in 'OPENAI_API_KEY'
  line 16  AIC005 MEDIUM   hardcoded secret in 'db_password'
  line 20  AIC001 HIGH     pickle.load() runs code from the file
  line 21  AIC001 HIGH     torch.load() without weights_only=True
  line 22  AIC001 HIGH     joblib.load() runs code from the file
  line 23  AIC006 HIGH     trust_remote_code=True executes code from the model repo
  line 23  AIC008 LOW      from_pretrained() without revision= (pin a commit hash)
  line 28  AIC001 HIGH     yaml.load() without SafeLoader; use yaml.safe_load
  line 32  AIC007 MEDIUM   TLS certificate verification disabled
  line 37  AIC002 CRITICAL model output flows into eval()
  line 37  AIC003 HIGH     eval() with a non-literal argument
  line 38  AIC002 CRITICAL model output flows into subprocess.run()
  line 38  AIC004 HIGH     subprocess.run() uses a shell
== fixed_app.py: 0 finding(s) ==
```

## Honest limits

The scanner is a pattern checker. It misses renamed imports (`from pickle import load as l`), data that travels through many functions and anything dynamic. The taint check only follows a name assigned directly from a model call. A clean result means "none of these patterns", not "safe". Use real tools in CI and review the code too.

## Optional: the real tools

```text
pip install bandit
bandit -r caisp-course/ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses/sample_app
```

Bandit reports its own rule IDs (for example for pickle, `yaml.load`, `shell=True` and `eval`). Semgrep (`semgrep --config p/python`) has rule packs you can extend with your own AI rules, such as "model output into eval". Compare their findings with `scanner.py`. Which ones does your scanner find that they do not, and the reverse? (Tool output varies by version.)

## Related

- Course lesson: [06 Tooling: SCA, SAST, DAST and AI firewalls](../../06-devsecops-tooling-for-ai.md)
- Repo: AI-generated code gate in [02 model-threats](../../../../02-llm-security/model-threats/README.md), pipeline lint in [06 cicd](../../../../06-ai-devsecops/cicd/README.md)
