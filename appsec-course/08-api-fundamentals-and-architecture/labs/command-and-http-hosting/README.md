# Lab: Commands, outputs, exit codes and hosting files over HTTP

**Course items:** "Working With Linux Command(s)", "Working With Command Outputs", "Working With Exit Code", "Hosting Files Using HTTP Server". **Lesson:** [05 Lab setup and command-line basics](../../05-lab-setup-and-command-line-basics.md).

**Time:** 40 minutes. **Tests:** 8, offline. **Safety:** the command runner is a **simulator**: it never launches a shell or a process (no `subprocess`, no `os.system`). The HTTP server binds to **127.0.0.1** on an ephemeral port and is shut down after each use. Only test systems you own or have written permission to test.

## Goal

Understand stdout vs stderr, exit codes (0 = success), `&&`/`||` chaining, and how to host a file for a lab exercise safely.

## Files

| File | Role |
|---|---|
| [cmdlab.py](cmdlab.py) | `CommandRunner` (models `true`, `false`, `echo`, `cat`, `grep`, `ls`, unknown commands) and `serve_dir` (Python `http.server` on loopback) |
| [demo.py](demo.py) | prints exit codes, chaining and a real loopback download |
| [test_aps_ch08_command_and_hosting.py](test_aps_ch08_command_and_hosting.py) | the tests |

## Run

```text
.venv/Scripts/python appsec-course/08-api-fundamentals-and-architecture/labs/command-and-http-hosting/demo.py
.venv/Scripts/python -m pytest appsec-course/08-api-fundamentals-and-architecture/labs/command-and-http-hosting -q
```

## Real output (the port changes each run)

```text
=== Exit codes (0 = success, non-zero = failure) ===
  $ true                     exit=0    stdout='' stderr=''
  $ false                    exit=1    stdout='' stderr=''
  $ echo hi                  exit=0    stdout='hi' stderr=''
  $ grep 403 access.log      exit=0    stdout='GET /admin 403' stderr=''
  $ grep 500 access.log      exit=1    stdout='' stderr=''
  $ cat missing.txt          exit=1    stdout='' stderr='cat: missing.txt: No such file or directory'
  $ frobnicate               exit=127  stdout='' stderr='frobnicate: command not found'

=== Chaining with && and || ===
  $ false && echo ran                    -> exit=1 stdout=''
  $ grep 500 access.log || echo not-found -> exit=0 stdout='not-found'
  $ true && echo yes                     -> exit=0 stdout='yes'

=== Hosting files over HTTP on 127.0.0.1 ===
  GET http://127.0.0.1:62270/hello.txt -> 200
  body: served over 127.0.0.1
```

## Steps

1. Predict each exit code before running the demo. Which one surprised you? (Usually `grep` returning 1 for "no match".)
2. Add a `_cmd_wc` method that counts lines of a fake file and returns 1 if the file is missing. Add a test.
3. Explain why `cat notes.txt missing.txt` writes to **both** stdout and stderr and still exits 1.
4. In `serve_dir`, change `"127.0.0.1"` to `"0.0.0.0"` (do not commit it). Who on your network could now read the folder? Change it back.
5. Fetch a missing file and confirm the 404 in the test.

## Run the real tool (hedged)

On the course lab machine (Linux):

```bash
mkdir -p /tmp/share && cd /tmp/share && echo hello > hello.txt
python3 -m http.server 8000 --bind 127.0.0.1 &
curl -s http://127.0.0.1:8000/hello.txt; echo "exit=$?"
curl -sf http://127.0.0.1:8000/nope.txt; echo "exit=$?"     # 22 with -f on a 404
kill %1
```

On Windows PowerShell: `python -m http.server 8000 --bind 127.0.0.1`, then `curl.exe -s http://127.0.0.1:8000/hello.txt; $LASTEXITCODE`.

## What you learned

- Data goes to stdout, errors to stderr; keep them apart when piping between tools.
- Exit code 0 means success; CI gates depend on tools exiting non-zero on findings.
- `&&` runs the next command only on success, `||` only on failure.
- A throwaway file server should bind to loopback and serve a dedicated folder.
