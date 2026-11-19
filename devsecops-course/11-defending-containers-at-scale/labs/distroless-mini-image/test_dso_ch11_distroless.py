import json
from pathlib import Path

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "surface")
CAT = json.loads((Path(__file__).parent / "fixtures" / "catalog.json").read_text())


def test_ranking_orders_by_surface():
    r = s.rank(CAT)
    assert r[0]["name"].startswith("scratch") and r[-1]["name"].startswith("ubuntu")
    assert [x["surface"] for x in r] == sorted(x["surface"] for x in r)


def test_pick_respects_shell_requirement():
    assert s.pick(CAT)["name"].startswith("scratch")
    assert s.pick(CAT, needs_shell=True)["name"].startswith("alpine")


def test_attacker_tools_counted():
    ubuntu = next(x for x in s.rank(CAT) if x["name"].startswith("ubuntu"))
    assert "curl" in ubuntu["attacker_tools"] and ubuntu["shell"]
