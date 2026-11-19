"""The application's ordinary FUNCTIONAL tests: what QA already runs. They contain no attack payloads.

An IAST agent rides along while these run. It can only report flows that these tests exercise.
"""

from pathlib import Path

from aisec_lab import load_lab_module

tinyapp = load_lab_module(str(Path(__file__).resolve()), "tinyapp")
Request = tinyapp.Request


def test_find_user_by_name(app):
    assert app.user_by_name(Request({"name": "alice"})) == [(1, "alice")]


def test_find_user_by_id(app):
    assert app.user_by_id(Request({"id": "2"})) == [(2, "bob")]


def test_ping_localhost(app):
    assert app.ping(Request({"host": "127.0.0.1"})) == "ok"


def test_read_doc(app):
    assert app.read_doc(Request({"file": "readme.txt"})).startswith("Welcome")


# the nightly suite forgot test_read_doc: the lab shows what that costs
CURRENT_SUITE = [test_find_user_by_name, test_find_user_by_id, test_ping_localhost]
FULL_SUITE = CURRENT_SUITE + [test_read_doc]


def run_suite(app, agent, suite):
    for t in suite:
        with agent.request(t.__name__):
            t(app)
