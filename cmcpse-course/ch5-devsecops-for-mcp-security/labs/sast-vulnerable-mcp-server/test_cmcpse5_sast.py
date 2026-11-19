"""SAST lab tests: the scanner finds every planted weakness, the fixed server is clean.

Run from the repository root:
    python -m pytest cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server -v
"""

import os
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

sast = load_lab_module(__file__, "mcp_sast")
secrets = load_lab_module(__file__, "secret_scan")
HERE = Path(__file__).resolve().parent


def rules(findings):
    return {f.rule for f in findings}


# ---------------------------------------------------------------- the two servers
def test_vulnerable_server_triggers_every_mcp_rule():
    found = rules(sast.scan_tree(HERE / "vulnerable_server"))
    assert {"MCP001", "MCP002", "MCP003", "MCP004", "MCP005", "MCP006", "SECRET"} <= found


def test_vulnerable_findings_point_at_the_right_files():
    by_rule = {}
    for f in sast.scan_tree(HERE / "vulnerable_server"):
        by_rule.setdefault(f.rule, set()).add(f.file)
    assert by_rule["MCP001"] == {"tools_shell.py"}
    assert by_rule["MCP002"] == {"tools_files.py"}
    assert by_rule["MCP003"] == {"tools_web.py"}
    assert by_rule["MCP004"] == {"server.py"}
    assert by_rule["MCP005"] == {"config.py"}
    assert by_rule["MCP006"] == {"server.py"}


def test_vulnerable_server_has_two_shell_findings():
    shell = [f for f in sast.scan_tree(HERE / "vulnerable_server") if f.rule == "MCP001"]
    assert len(shell) == 2  # subprocess shell=True and os.system


def test_fixed_server_is_clean():
    findings = sast.scan_tree(HERE / "fixed_server")
    assert findings == [], [str(f) for f in findings]


def test_findings_drop_after_the_fix():
    before = len(sast.scan_tree(HERE / "vulnerable_server"))
    after = len(sast.scan_tree(HERE / "fixed_server"))
    assert before >= 8 and after == 0


def test_every_secret_in_the_lab_is_marked_fake():
    found = secrets.scan_tree(HERE / "vulnerable_server")
    assert len(found) >= 4
    assert all(s.fake for s in found), "a lab fixture contains something that is not marked FAKE"


@pytest.mark.skipif(not os.environ.get("MY_FIX_DIR"), reason="set MY_FIX_DIR to your fixed copy to check it")
def test_learner_fix_is_clean():
    findings = sast.scan_tree(os.environ["MY_FIX_DIR"])
    assert findings == [], [str(f) for f in findings]


# ---------------------------------------------------------------- one rule at a time
def scan(src):
    return rules(sast.scan_source(src, "t.py"))


def test_mcp001_shell_true_and_os_system_and_eval():
    assert "MCP001" in scan("import subprocess\ndef f(x):\n    subprocess.run('ls ' + x, shell=True)\n")
    assert "MCP001" in scan("import os\ndef f(x):\n    os.system(x)\n")
    assert "MCP001" in scan("def f(x):\n    return eval(x)\n")


def test_mcp001_argument_list_is_fine():
    assert "MCP001" not in scan("import subprocess\ndef f(x):\n    subprocess.run(['ls', x], shell=False)\n")
    assert "MCP001" not in scan("def f():\n    return eval('1 + 1')\n")


def test_mcp002_join_without_canonicalization():
    assert "MCP002" in scan("import os\ndef f(n):\n    return open(os.path.join('/data', n)).read()\n")
    assert "MCP002" in scan("from pathlib import Path\ndef f(n):\n    return (Path('/data') / n).read_text()\n")


def test_mcp002_resolve_alone_is_not_enough():
    src = "from pathlib import Path\ndef f(n):\n    return (Path('/data') / n).resolve().read_text()\n"
    assert "MCP002" in scan(src)


def test_mcp002_resolve_and_containment_check_passes():
    src = (
        "from pathlib import Path\n"
        "def f(n):\n"
        "    p = (Path('/data') / n).resolve()\n"
        "    if not p.is_relative_to(Path('/data')):\n"
        "        raise ValueError\n"
        "    return p.read_text()\n"
    )
    assert "MCP002" not in scan(src)


def test_mcp002_ignores_plain_division():
    assert "MCP002" not in scan("def f(a, b):\n    return a / b\n")


def test_mcp003_ssrf_and_guard():
    bad = "import requests\ndef f(url):\n    return requests.get(url).text\n"
    good = "import requests\ndef f(url):\n    validate_url(url)\n    return requests.get(url).text\n"
    assert "MCP003" in scan(bad)
    assert "MCP003" not in scan(good)
    assert "MCP003" not in scan("import requests\ndef f():\n    return requests.get('https://example.com')\n")


def test_mcp004_secret_in_description_literal_and_fstring():
    assert "MCP004" in scan("T = {'name': 'x', 'description': 'Use API key: abc'}\n")
    assert "MCP004" in scan("T = {'description': f'Tool. token {config.GITHUB_TOKEN}'}\n")
    assert "MCP004" in scan("tool(description='key AKIAFAKEEXAMPLEKEY12')\n")
    assert "MCP004" not in scan("T = {'description': 'Read a note by name.'}\n")


def test_mcp005_bind_all_interfaces():
    assert "MCP005" in scan("HOST = '0.0.0.0'\n")
    assert "MCP005" in scan("serve(host='::', port=1)\n")
    assert "MCP005" not in scan("HOST = '127.0.0.1'\n")


def test_mcp006_verbose_errors():
    assert "MCP006" in scan("import traceback\ndef h():\n    try:\n        f()\n    except Exception:\n        return {'e': traceback.format_exc()}\n")
    assert "MCP006" in scan("def h():\n    try:\n        f()\n    except Exception as e:\n        return {'error': str(e)}\n")
    assert "MCP006" in scan("def h():\n    try:\n        f()\n    except Exception as e:\n        return f'failed: {e}'\n")


def test_mcp006_logging_and_generic_message_pass():
    src = "def h():\n    try:\n        f()\n    except Exception as e:\n        log.exception('x')\n        return {'error': 'tool error'}\n"
    assert "MCP006" not in scan(src)
    safe = "def h():\n    try:\n        f()\n    except InputError as e:\n        return {'error': e.public_message}\n"
    assert "MCP006" not in scan(safe)


def test_scanner_only_parses_and_never_runs_code():
    marker = Path(tempfile.mkdtemp()) / "ran.txt"
    src = f"open({str(marker)!r}, 'w').write('x')\nimport os\nos.system('echo hi')\n"
    sast.scan_source(src, "t.py")
    assert not marker.exists()


def test_cli_exit_codes():
    assert sast.main([str(HERE / "vulnerable_server")]) == 1
    assert sast.main([str(HERE / "fixed_server")]) == 0


# ---------------------------------------------------------------- secret scanner
@pytest.mark.parametrize(
    "line,kind",
    [
        ('KEY = "AKIAFAKEEXAMPLEKEY12"', "aws-access-key-id"),
        ('T = "ghp_FAKE0123456789abcdefghijklmnopqrstuv"', "github-token"),
        ('K = "sk-FAKE0123456789abcdefABCDEF0123"', "api-key-sk"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private-key-block"),
        ('password = "hunter2hunter2"', "generic-assignment"),
    ],
)
def test_named_patterns(line, kind):
    assert kind in {f.kind for f in secrets.scan_text(line)}


def test_entropy_rule_catches_random_looking_strings():
    value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEYFAKE"
    assert secrets.shannon_entropy(value) >= secrets.ENTROPY_THRESHOLD
    assert "high-entropy-string" in {f.kind for f in secrets.scan_text(f'x = "{value}"')}


def test_entropy_ignores_plain_words_and_placeholders():
    assert secrets.scan_text('NAME = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"') == []
    assert secrets.scan_text('api_key = "<your-api-key-here>"') == []
    assert secrets.scan_text('api_key = os.environ["API_KEY"]') == []


def test_findings_are_redacted_and_marked_fake():
    [finding] = secrets.scan_text('K = "AKIAFAKEEXAMPLEKEY12"')
    assert "AKIAFAKEEXAMPLEKEY12" not in str(finding)
    assert finding.preview.startswith("AKIA...")
    assert finding.fake is True


def test_unmarked_key_is_not_called_fake():
    [finding] = secrets.scan_text('K = "AKIAZZZZZZZZZZZZZZZZ"')
    assert finding.fake is False
