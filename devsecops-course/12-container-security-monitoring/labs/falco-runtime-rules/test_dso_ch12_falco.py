import json
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

f = load_lab_module(__file__, "falco_lite")
HERE = Path(__file__).parent
RULES = f.load((HERE / "rules.yaml").read_text())
EVENTS = [json.loads(l) for l in (HERE / "events.jsonl").read_text().splitlines() if l.strip()]
ALERTS = f.run(RULES, EVENTS)


def hits(rule):
    return [a["n"] for a in ALERTS if a["rule"] == rule]


def test_shell_in_container_only_with_tty_and_container():
    assert hits("Terminal shell in container") == [1]  # not host (2), not tty=0 (3)


def test_write_below_etc_excludes_package_managers():
    assert hits("Write below etc in container") == [4]


def test_sensitive_read_excludes_trusted_reader():
    assert hits("Read sensitive file in container") == [6]


def test_miner_port_connect():
    assert hits("Outbound connection to a miner port") == [8]


def test_output_substitution():
    a = [x for x in ALERTS if x["n"] == 8][0]
    assert "203.0.113.50:3333" in a["text"] and a["priority"] == "CRITICAL"


def test_condition_parser_precedence_and_not():
    ast = f.Parser(f.tokenize("a.x = 1 or a.y = 2 and not a.z = 3"), {}, {}).parse()
    assert f.evaluate(ast, {"a.x": 1})
    assert f.evaluate(ast, {"a.y": 2, "a.z": 4})
    assert not f.evaluate(ast, {"a.y": 2, "a.z": 3})


def test_in_list_and_missing_field_is_false():
    ast = f.Parser(f.tokenize("proc.name in (a, 'b c')"), {}, {}).parse()
    assert f.evaluate(ast, {"proc.name": "b c"}) and not f.evaluate(ast, {})


def test_numeric_compare_and_bad_syntax():
    ast = f.Parser(f.tokenize("fd.sport >= 1000"), {}, {}).parse()
    assert f.evaluate(ast, {"fd.sport": 3333}) and not f.evaluate(ast, {"fd.sport": 80})
    with pytest.raises(ValueError):
        f.Parser(f.tokenize("proc.name ~~ x"), {}, {}).parse()
