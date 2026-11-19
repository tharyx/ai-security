"""Command exit-code semantics (simulated) and a loopback file host.

Two independent, offline pieces that teach the CASP 1 "lab setup" lines:

1. ``CommandRunner`` is a *simulator*. It never spawns a shell or a process
   (no ``subprocess``, no ``os.system``): it models a handful of familiar
   commands as pure Python so a learner can see stdout, stderr and, above all,
   the **exit code** (0 = success, non-zero = failure) that scripts and CI
   pipelines branch on. Chaining with ``&&`` and ``||`` is modelled too.

2. ``serve_dir`` starts Python's own ``http.server`` bound to **127.0.0.1**
   on an ephemeral port in a daemon thread, so a test can host a temp
   directory and fetch a file over real HTTP without touching the network.

Only test systems you own or have written permission to test.
"""
from __future__ import annotations

import http.server
import threading
from dataclasses import dataclass


@dataclass
class Result:
    stdout: str
    stderr: str
    code: int  # the exit / return code

    @property
    def ok(self) -> bool:
        return self.code == 0


class CommandRunner:
    """A tiny, safe stand-in for a shell. Models exit-code behaviour only."""

    def __init__(self, files: dict | None = None):
        # A fake filesystem: name -> text contents.
        self.files = dict(files or {})

    def run(self, command: str) -> Result:
        """Run one command string, honouring ``&&`` and ``||`` chaining.

        ``a && b`` runs ``b`` only if ``a`` succeeded (exit 0).
        ``a || b`` runs ``b`` only if ``a`` failed (exit non-zero).
        Returns the Result of the last command that actually ran.
        """
        # Tokenise on the two operators while keeping them.
        import re
        parts = re.split(r"\s*(&&|\|\|)\s*", command.strip())
        result = self._run_one(parts[0])
        i = 1
        while i < len(parts) - 1:
            op, nxt = parts[i], parts[i + 1]
            if op == "&&" and result.ok:
                result = self._run_one(nxt)
            elif op == "||" and not result.ok:
                result = self._run_one(nxt)
            # else: short-circuit, keep the current result
            i += 2
        return result

    def _run_one(self, cmd: str) -> Result:
        argv = cmd.split()
        if not argv:
            return Result("", "", 0)
        name, args = argv[0], argv[1:]
        handler = getattr(self, f"_cmd_{name}", None)
        if handler is None:
            # The shell convention for "command not found".
            return Result("", f"{name}: command not found", 127)
        return handler(args)

    # --- modelled commands -------------------------------------------------
    def _cmd_true(self, args):
        return Result("", "", 0)

    def _cmd_false(self, args):
        return Result("", "", 1)

    def _cmd_echo(self, args):
        return Result(" ".join(args), "", 0)

    def _cmd_cat(self, args):
        out, err, code = [], [], 0
        for name in args:
            if name in self.files:
                out.append(self.files[name])
            else:
                err.append(f"cat: {name}: No such file or directory")
                code = 1
        return Result("\n".join(out), "\n".join(err), code)

    def _cmd_grep(self, args):
        if len(args) < 2:
            return Result("", "grep: usage: grep PATTERN FILE", 2)
        pattern, name = args[0], args[1]
        if name not in self.files:
            return Result("", f"grep: {name}: No such file or directory", 2)
        matches = [ln for ln in self.files[name].splitlines() if pattern in ln]
        # grep exits 1 when it finds nothing. This trips up many scripts.
        return Result("\n".join(matches), "", 0 if matches else 1)

    def _cmd_ls(self, args):
        if args and args[0] not in self.files:
            return Result("", f"ls: cannot access '{args[0]}': No such file or directory", 2)
        return Result("\n".join(sorted(self.files)), "", 0)


# --- loopback file host ----------------------------------------------------
class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):  # keep test output clean
        pass


def serve_dir(directory: str):
    """Serve ``directory`` over HTTP on 127.0.0.1:<ephemeral>. Returns (httpd, port).

    Call ``httpd.shutdown()`` and ``httpd.server_close()`` when done. The
    handler is SimpleHTTPRequestHandler, which reads the whole request before
    replying, so Windows does not reset the connection.
    """
    def handler(*args, **kwargs):
        return _QuietHandler(*args, directory=directory, **kwargs)

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port
