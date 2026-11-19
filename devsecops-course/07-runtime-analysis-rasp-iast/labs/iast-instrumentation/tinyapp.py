"""A tiny web-app backend with three kinds of sinks. Nothing here touches the network or a shell.

* ``Database.execute``  -> sqlite (in-memory)
* ``Shell.run``         -> a STUB that records the command; it never runs it
* ``Files.open_file``   -> an in-memory virtual file system with FAKE content

Handlers take a ``Request`` whose values are ``TaintedStr`` (the *source*). The first three handlers are
vulnerable on purpose; ``user_by_id`` is the safe version (bound parameter).
"""

from __future__ import annotations

import posixpath
import sqlite3
import sys
from pathlib import Path

from aisec_lab import load_lab_module

_t = load_lab_module(str(Path(__file__).resolve()), "taint")
TaintedStr = _t.TaintedStr


class Request:
    def __init__(self, params: dict):
        # SOURCE: every request value becomes tainted, labelled with where it came from
        self.args = {k: TaintedStr(v, f"request.args['{k}']") for k, v in params.items()}


class Database:
    def __init__(self):
        self.con = sqlite3.connect(":memory:")
        self.con.execute("CREATE TABLE users (id INTEGER, name TEXT, role TEXT)")
        self.con.executemany("INSERT INTO users VALUES (?,?,?)", [(1, "alice", "user"), (2, "bob", "admin")])

    def execute(self, sql, params=()):  # SINK 1
        return self.con.execute(str(sql), params).fetchall()


class Shell:
    def __init__(self):
        self.executed: list = []

    def run(self, cmd):  # SINK 2 (stub: records, never executes)
        self.executed.append(str(cmd))
        return "ok"


class Files:
    VFS = {
        "/srv/docs/readme.txt": "Welcome (fake doc)",
        "/etc/passwd": "root:x:0:0:FAKE-CANARY",
    }

    def open_file(self, path):  # SINK 3
        return self.VFS.get(posixpath.normpath(str(path)), "")


class App:
    def __init__(self):
        self.db, self.shell, self.files = Database(), Shell(), Files()

    # --- vulnerable handlers
    def user_by_name(self, req):
        sql = "SELECT id, name FROM users WHERE name = '" + req.args["name"] + "'"
        return self.db.execute(sql)

    def ping(self, req):
        return self.shell.run("ping -c 1 " + req.args["host"])

    def read_doc(self, req):
        return self.files.open_file("/srv/docs/" + req.args["file"])

    # --- safe handler (bound parameter): tainted data goes in ``params``, not in the SQL text
    def user_by_id(self, req):
        return self.db.execute("SELECT id, name FROM users WHERE id = ?", (req.args["id"],))

    # --- looks safe but the taint is lost (f-string): a false negative for the toy agent
    def user_by_name_fstring(self, req):
        name = req.args["name"]
        return self.db.execute(f"SELECT id, name FROM users WHERE name = '{name}'")


def line_of(func_name: str) -> int:
    """Helper for docs/tests: first line number of a handler."""
    import inspect

    return inspect.getsourcelines(getattr(App, func_name))[1]


__all__ = ["App", "Request", "Database", "Shell", "Files", "sys"]
