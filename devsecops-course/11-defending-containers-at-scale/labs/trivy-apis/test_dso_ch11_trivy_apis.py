import importlib.util
import json
import sys
from pathlib import Path

from aisec_lab import load_lab_module

api = load_lab_module(__file__, "trivy_mock_api")
_p = Path(__file__).resolve().parents[1] / "trivy-vuln-scan" / "trivy_report.py"
_spec = importlib.util.spec_from_file_location("dso_ch11_trivy_report_for_api", _p)
tr = importlib.util.module_from_spec(_spec)
sys.modules["dso_ch11_trivy_report_for_api"] = tr
_spec.loader.exec_module(tr)
REP = json.loads((_p.parent / "fixtures" / "trivy-report.json").read_text())
TOKEN = "test-token-only"


def _run():
    srv = api.make_server({"img:1": REP}, TOKEN)
    api.serve_in_thread(srv)
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_server_binds_loopback_only():
    srv, _ = _run()
    try:
        assert srv.server_address[0] == "127.0.0.1"
    finally:
        srv.shutdown()


def test_missing_or_wrong_token_is_401():
    srv, base = _run()
    try:
        assert api.scan(base, "img:1", "")[0] == 401
        assert api.scan(base, "img:1", "wrong")[0] == 401
    finally:
        srv.shutdown()


def test_unknown_target_404_and_valid_scan_200():
    srv, base = _run()
    try:
        assert api.scan(base, "nope", TOKEN)[0] == 404
        code, body = api.scan(base, "img:1", TOKEN)
        assert code == 200 and tr.summary(body)["CRITICAL"] == 2
    finally:
        srv.shutdown()


def test_gate_on_api_result():
    srv, base = _run()
    try:
        _, body = api.scan(base, "img:1", TOKEN)
        ok, why = tr.gate(body, fail_on="CRITICAL", fail_on_secrets=False)
        assert not ok and len(why) == 2
    finally:
        srv.shutdown()
