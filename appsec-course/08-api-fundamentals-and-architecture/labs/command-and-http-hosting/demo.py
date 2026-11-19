import os
import sys
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cmdlab as c  # noqa: E402

runner = c.CommandRunner({
    "access.log": "GET /ok 200\nGET /admin 403\nPOST /login 200",
    "notes.txt": "hello world",
})

print("=== Exit codes (0 = success, non-zero = failure) ===")
for cmd in ["true", "false", "echo hi", "grep 403 access.log",
            "grep 500 access.log", "cat missing.txt", "frobnicate"]:
    r = runner.run(cmd)
    print(f"  $ {cmd:<24} exit={r.code:<4} stdout={r.stdout!r} stderr={r.stderr!r}")

print("\n=== Chaining with && and || ===")
for cmd in ["false && echo ran", "grep 500 access.log || echo not-found",
            "true && echo yes"]:
    r = runner.run(cmd)
    print(f"  $ {cmd:<36} -> exit={r.code} stdout={r.stdout!r}")

print("\n=== Hosting files over HTTP on 127.0.0.1 ===")
with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "hello.txt"), "w", encoding="utf-8") as f:
        f.write("served over 127.0.0.1")
    httpd, port = c.serve_dir(d)
    try:
        url = f"http://127.0.0.1:{port}/hello.txt"
        with urllib.request.urlopen(url, timeout=5) as resp:
            print(f"  GET {url} -> {resp.status}")
            print("  body:", resp.read().decode())
    finally:
        httpd.shutdown()
        httpd.server_close()
