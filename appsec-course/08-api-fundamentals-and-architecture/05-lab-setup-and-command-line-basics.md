# Lesson 05: Lab Setup and Command-Line Basics

**Syllabus items covered:** "Understanding The Lab Setup", "Working With Linux Command(s)", "Working With Command Outputs", "Working With Exit Code", "Hosting Files Using HTTP Server" ([CASP 1]).

**Time:** 60 minutes. **Lab:** [command-and-http-hosting](labs/command-and-http-hosting/README.md). **Background:** [Linux for security analysts](../../cybersecurity-track/01-it-fundamentals/03-linux-for-security-analysts.md) in the cybersecurity track.

> You already live in a shell as a DBA (`sqlplus -s`, `rman`, cron jobs that check `$?`). This lesson only maps that habit onto the API course labs, and gives PowerShell equivalents because your laptop is Windows.

## 1. Understanding the lab setup

**The course lab (hedged: check your course portal).** Practical DevSecOps courses usually give you a browser-based lab machine (Linux) with the target APIs and tools (curl, Burp Suite, Postman, ffuf, sqlmap, Python) pre-installed, reachable for a limited time per exercise. Exams are hands-on and time-boxed: practise doing things from the command line quickly. Check your exam guide for the exact environment.

**This repository's labs** run on your own laptop, offline:

| What | Command (from the repo root) |
|---|---|
| Run one chapter's tests | `.venv/Scripts/python -m pytest appsec-course/08-api-fundamentals-and-architecture -q` |
| Run a lab demo | `.venv/Scripts/python appsec-course/08-api-fundamentals-and-architecture/labs/http-anatomy/demo.py` |
| Needs | Python standard library and `pytest`. No Docker, no internet, no Burp. |

Targets in these labs are in-process Python functions or a server bound to `127.0.0.1`. Only test systems you own or have written permission to test.

## 2. Working with Linux commands

The commands you will use most in API labs, with PowerShell equivalents:

| Task | bash (course lab) | PowerShell (your laptop) |
|---|---|---|
| Where am I / list | `pwd`, `ls -la` | `Get-Location`, `Get-ChildItem -Force` |
| Read a file | `cat file`, `less file` | `Get-Content file` |
| Search text | `grep -i token app.log` | `Select-String -Pattern token app.log` |
| First / last lines | `head -n 20`, `tail -f app.log` | `Get-Content -TotalCount 20`, `Get-Content -Wait` |
| Call an API | `curl -s https://host/api` | `curl.exe -s https://host/api` (or `Invoke-RestMethod`) |
| Pretty JSON | `curl -s ... \| jq .` | `Invoke-RestMethod ... \| ConvertTo-Json -Depth 5` |
| Environment variable | `export TOKEN=...`, `echo $TOKEN` | `$env:TOKEN = "..."`, `$env:TOKEN` |
| Processes and ports | `ps aux`, `ss -ltnp` | `Get-Process`, `Get-NetTCPConnection -State Listen` |
| Encode / decode base64 | `echo -n 'u:p' \| base64`, `base64 -d` | `[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('u:p'))` |

Tip: put secrets such as tokens in environment variables, not on the command line, because command lines end up in shell history and process listings.

## 3. Working with command outputs

Every process has three standard streams:

| Stream | Number | Use |
|---|---|---|
| stdin | 0 | input |
| stdout | 1 | normal output (data) |
| stderr | 2 | errors and progress messages |

```bash
curl -s https://api.lab/items > items.json          # stdout to a file
curl -s https://api.lab/items 2> errors.txt         # stderr to a file
curl -s https://api.lab/items | jq '.[].id'         # pipe stdout into another command
ffuf ... -o result.json -of json                     # many tools also write their own report files
```

Keep data (stdout) and noise (stderr) apart so you can pipe results into the next tool. `curl -s` silences the progress meter (stderr) and `-o file` writes the body to a file; `-w '%{http_code}\n'` prints just the status code, which is very handy in API testing loops.

## 4. Working with exit codes

Every command returns an **exit code** (also called return code or status): **0 means success**, anything else means failure. Scripts and CI pipelines branch on it.

| Code | Usual meaning |
|---|---|
| 0 | success |
| 1 | general failure; also "no match" for `grep` |
| 2 | misuse / error (for example `grep` could not read a file) |
| 126 | found but not executable |
| 127 | command not found |
| 128+N | killed by signal N (130 = Ctrl-C) |

```bash
grep -q "403" access.log; echo $?        # 0 if found, 1 if not
curl -sf https://api.lab/health || echo "health check failed"   # -f: exit 22 on HTTP >= 400
make test && deploy.sh                    # deploy only if tests passed
```

PowerShell: `$LASTEXITCODE` for native programs, `$?` for the last command's success. Remember that in PowerShell 5.1 `&&` and `||` do not exist; use `if ($LASTEXITCODE -eq 0) { ... }`.

**Why it matters for security:** a CI security gate (SAST, SCA, a spec linter, the gate in the [api-threat-model lab](labs/api-threat-model/README.md)) works only because the tool **exits non-zero** on findings. A scanner wrapped as `scanner || true` silently disables the gate. Also note the classic trap: `curl` exits 0 on an HTTP 500 unless you pass `-f`/`--fail`.

The [lab](labs/command-and-http-hosting/README.md) uses a **simulated** command runner (no shell is ever launched) to show exit codes, the stdout/stderr split, and `&&`/`||` short-circuiting.

## 5. Hosting files using an HTTP server

In API labs you often need to serve a file over HTTP: a payload for an SSRF test, a JWKS file for a JWT key-confusion exercise, a webhook receiver, or a file to download onto the lab machine.

```bash
# serve the current directory on port 8000, loopback only
python3 -m http.server 8000 --bind 127.0.0.1
# from another terminal
curl -s http://127.0.0.1:8000/payload.json
```

PowerShell: `python -m http.server 8000 --bind 127.0.0.1` works the same.

Safety rules:

- **Bind to 127.0.0.1** unless the exercise really needs another host to reach you. The default binds all interfaces, which exposes the folder to your network.
- **Serve a dedicated empty folder**, never your home directory (SSH keys, cloud credentials).
- `http.server` is for labs only: no TLS, no authentication, minimal security checks. The Python docs say it is not recommended for production.
- Stop it when done (Ctrl-C).

The lab starts `http.server` on `127.0.0.1` with port `0` (the OS picks a free port), serves a temporary directory, downloads a file, checks a 404 for a missing one, and shuts the server down.

## 6. Scenario: the green pipeline that never scanned

A team's pipeline step was `dependency-scan --fail-on high | tee scan.txt`. It was green for months. A pipe returns the exit code of the **last** command (`tee`, always 0) unless `set -o pipefail` is set, so high-severity findings never failed the build. Fix: `set -euo pipefail` at the top of bash steps, and a test that the gate fails on a known-bad fixture.

## 7. Self-check

1. What exit code does `grep` return when it finds nothing, and why can that break a script?
2. Why should a lab HTTP server bind to `127.0.0.1`?
3. What does `curl -sf` change compared with `curl -s`?

Back to the [chapter README](README.md).
