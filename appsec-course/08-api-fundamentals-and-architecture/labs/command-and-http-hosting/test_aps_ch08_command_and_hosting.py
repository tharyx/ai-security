import os
import tempfile
import urllib.request

from aisec_lab import load_lab_module

c = load_lab_module(__file__, "cmdlab")

FILES = {
    "access.log": "GET /ok 200\nGET /admin 403\nPOST /login 200",
    "notes.txt": "hello world",
}


def test_success_is_exit_code_zero():
    r = c.CommandRunner(FILES).run("true")
    assert r.code == 0 and r.ok


def test_failure_is_nonzero_exit_code():
    r = c.CommandRunner(FILES).run("false")
    assert r.code == 1 and not r.ok


def test_command_not_found_is_127():
    r = c.CommandRunner(FILES).run("frobnicate --now")
    assert r.code == 127
    assert "command not found" in r.stderr


def test_stdout_and_stderr_are_separate_streams():
    r = c.CommandRunner(FILES).run("cat notes.txt missing.txt")
    assert "hello world" in r.stdout
    assert "No such file" in r.stderr
    assert r.code == 1  # one file failed


def test_grep_exit_code_signals_a_match_or_no_match():
    runner = c.CommandRunner(FILES)
    hit = runner.run("grep 403 access.log")
    miss = runner.run("grep 500 access.log")
    assert hit.code == 0 and "403" in hit.stdout
    assert miss.code == 1 and miss.stdout == ""  # grep: nothing found == exit 1


def test_and_chaining_short_circuits_on_failure():
    runner = c.CommandRunner(FILES)
    # 'false && echo ran' must NOT run the echo.
    r = runner.run("false && echo ran")
    assert r.stdout == "" and r.code == 1


def test_or_chaining_runs_fallback_on_failure():
    runner = c.CommandRunner(FILES)
    r = runner.run("grep 500 access.log || echo not-found")
    assert r.stdout == "not-found" and r.code == 0


def test_http_server_hosts_a_temp_dir_on_loopback():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "hello.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("served over 127.0.0.1")
        httpd, port = c.serve_dir(d)
        try:
            url = f"http://127.0.0.1:{port}/hello.txt"
            with urllib.request.urlopen(url, timeout=5) as resp:
                assert resp.status == 200
                body = resp.read().decode()
            assert body == "served over 127.0.0.1"
            # a missing file returns 404
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/nope.txt", timeout=5)
                missing_status = 200
            except urllib.error.HTTPError as e:
                missing_status = e.code
            assert missing_status == 404
        finally:
            httpd.shutdown()
            httpd.server_close()
