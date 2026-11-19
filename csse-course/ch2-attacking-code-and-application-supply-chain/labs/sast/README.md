# Lab: Static Application Security Testing (SAST)

**Course exercise:** "Static Application Security Testing (SAST)". Lessons: [08 section 2](../../08-technologies-and-solutions-for-securing-applications.md#2-sast), [05](../../05-attacks-on-the-application-side.md). Related: [CAISP ch4 ai-code-weaknesses](../../../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses/), [CMCPSE sast-vulnerable-mcp-server](../../../../cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server/README.md). Real tool: [real-tools/semgrep-and-bandit.md](../../real-tools/semgrep-and-bandit.md).

**Time:** 45 minutes. **Safety:** the scanner **parses** source with `ast` and never imports or runs it. The vulnerable app is a fixture; its secret is a FAKE string.

## What it does

`scanner.py` has 12 rules (CWE-tagged) and a small **taint** tracker: values from `request.*` are "tainted", taint flows through assignments, and sanitizers (`int`, `escape`, `validate_url`, `safe_join`...) clear it. A tainted value reaching a sink raises the severity.

| Rule | Finds |
|---|---|
| SAST001 | `eval` / `exec` |
| SAST002 | `os.system`, `subprocess(..., shell=True)` |
| SAST003 | `pickle.loads`, `yaml.load` without a safe loader |
| SAST004 | hardcoded secrets in variables named password/token/key |
| SAST005 | SQL built by string formatting |
| SAST006 | `md5` / `sha1` |
| SAST007 | `requests(..., verify=False)` |
| SAST008 | `app.run(debug=True)` |
| SAST009 | tainted text in `render_template_string` / `Markup` |
| SAST010 | tainted path in `open()` |
| SAST011 | tainted URL to an HTTP client (SSRF) |
| SAST012 | `tempfile.mktemp` |

`fixtures/fixed_app.py` fixes every issue and the scanner reports **zero** findings.

## Run

```text
.venv/Scripts/python csse-course/ch2-attacking-code-and-application-supply-chain/labs/sast/demo.py
.venv/Scripts/python -m pytest csse-course/ch2-attacking-code-and-application-supply-chain/labs/sast
```

## Expected output (real run)

```text
== vulnerable_app.py: 14 finding(s), gate exit code 1 ==
  line  14 SAST004 [high    ] CWE-798  hardcoded secret in variable 'API_TOKEN'
  line  21 SAST005 [critical] CWE-89   SQL built by string formatting; use parameters
  line  28 SAST009 [high    ] CWE-79   render_template_string() with user-controlled text (XSS or template injection)
  line  34 SAST002 [critical] CWE-78   shell command execution
  line  35 SAST002 [critical] CWE-78   shell command execution
  line  42 SAST003 [high    ] CWE-502  pickle.loads on untrusted data can run code
  line  43 SAST003 [high    ] CWE-502  yaml.load without a safe Loader
  line  49 SAST001 [critical] CWE-95   eval() on dynamic input
  line  55 SAST010 [high    ] CWE-22   file path comes from the request (path traversal)
  line  61 SAST007 [high    ] CWE-295  TLS verification disabled
  line  61 SAST011 [high    ] CWE-918  outbound request to a user-controlled URL (SSRF)
  line  65 SAST006 [medium  ] CWE-328  hashlib.md5 is weak; do not use it for passwords or signatures
  line  69 SAST012 [low     ] CWE-377  mktemp is racy; use mkstemp or NamedTemporaryFile
  line  73 SAST008 [medium  ] CWE-489  debug mode enabled
== fixed_app.py: 0 finding(s), gate exit code 0 ==
```

## Break it yourself

1. Hide the taint: `x = request.args["a"]; y = [x][0]; open(y)`. Does the scanner catch it? (No. Simple taint tracking misses containers and function calls. This is a false negative; real tools do deeper data-flow.)
2. Add `# nosec`-style suppression. Who may use it? (Require a reason and review.)
3. Write a rule for `random.random()` used for tokens. What is the fix? (`secrets.token_urlsafe`.)

## Limits

Regex-and-AST rules find patterns, not every bug. Expect **false positives** (safe code flagged) and **false negatives** (missed flows). Tune rules, baseline old findings, and gate only on new high-confidence ones.
