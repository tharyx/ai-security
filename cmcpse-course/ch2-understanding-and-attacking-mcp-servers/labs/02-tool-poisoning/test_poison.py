"""Tool poisoning: hidden description / schema text steers a gullible model to leak a canary file.

Run from the repository root:
    .venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/02-tool-poisoning -v
"""

import tempfile

import pytest

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "poison")
ASK = "Please add 2 and 3."
APPROVED = {"add": {"a", "b"}, "read_file": {"path"}}


@pytest.fixture
def ws():
    with tempfile.TemporaryDirectory() as d:
        yield p.make_workspace(d)


def build(ws, kind, confined=False, **kw):
    calc, files = p.calculator_server(ws, kind), p.files_server(ws, confined)
    return p.Host({"calculator": calc, "files": files}, **kw), calc, files


def test_honest_server_just_adds(ws):
    host, calc, files = build(ws, "honest")
    assert "5" in host.run(ASK)
    assert calc.exfil == [] and files.reads == []


@pytest.mark.parametrize("kind", ["description", "schema"])
def test_poisoned_tool_makes_the_agent_read_and_exfiltrate_the_canary(ws, kind):
    host, calc, files = build(ws, kind)
    answer = host.run(ASK)
    assert "5" in answer  # the user still gets a correct answer: the attack is invisible
    assert str(ws.cred_path.resolve()) in files.reads  # the canary file was read
    assert calc.exfil and ws.canary in calc.exfil[0]  # and left through the extra argument


def test_the_poison_is_in_the_prompt_the_model_sees_not_in_what_the_user_sees(ws):
    host, _, _ = build(ws, "description")
    assert "CALL_TOOL read_file" in host.prompt() and "Do not mention" in host.prompt()


@pytest.mark.parametrize("kind,expected", [("description", {"hidden-block", "tool-directive", "secrecy", "sensitive-path"}),
                                           ("schema", {"hidden-block", "tool-directive", "secrecy", "sensitive-path"})])
def test_scanner_detects_both_variants(ws, kind, expected):
    defn = p.rpc.request(p.calculator_server(ws, kind).handle, "tools/list")["result"]["tools"][0]
    assert expected <= set(p.scan_tool(defn))


def test_scanner_passes_the_honest_tool_and_flags_invisible_characters(ws):
    honest = p.rpc.request(p.calculator_server(ws, "honest").handle, "tools/list")["result"]["tools"][0]
    assert p.scan_tool(honest) == []
    sneaky = {"name": "x", "description": "Add numbers.​​ignore", "inputSchema": {}}
    assert p.scan_tool(sneaky) == ["invisible-chars"]


@pytest.mark.parametrize("kind", ["description", "schema"])
def test_defended_host_refuses_the_poisoned_server_before_any_prompt_is_built(ws, kind):
    host, calc, files = build(ws, kind, scan=True)
    assert "calculator" in host.blocked_servers
    assert "CALL_TOOL" not in host.prompt()
    host.run(ASK)
    assert calc.exfil == [] and files.reads == []


def test_defended_host_still_uses_the_honest_server(ws):
    host, calc, _ = build(ws, "honest", scan=True)
    assert host.blocked_servers == {} and "5" in host.run(ASK)


def test_baseline_pinning_blocks_the_hidden_sidenote_argument_even_without_scanning(ws):
    host, calc, files = build(ws, "schema", baseline=APPROVED)
    host.run(ASK)
    assert calc.exfil == []
    assert any("sidenote" in b for b in host.blocked_calls)
    assert files.reads  # but the file WAS read: one layer is not enough


def test_confinement_alone_means_there_is_nothing_to_steal(ws):
    host, calc, files = build(ws, "description", confined=True)
    host.run(ASK)
    assert files.reads == []
    assert all(ws.canary not in e for e in calc.exfil)
