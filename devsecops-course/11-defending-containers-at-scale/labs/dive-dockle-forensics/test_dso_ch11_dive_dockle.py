import json
from pathlib import Path

from aisec_lab import load_lab_module

lf = load_lab_module(__file__, "layer_forensics")
FIX = Path(__file__).parent / "fixtures"
LEAKY = json.loads((FIX / "image_leaky.json").read_text())
CLEAN = json.loads((FIX / "image_clean.json").read_text())


def test_final_fs_hides_deleted_file_but_layer_keeps_it():
    assert "app/.env" not in lf.final_fs(LEAKY)
    d = lf.deleted_but_present(LEAKY)
    assert d[0]["path"] == "app/.env" and d[0]["added_in"] == "L2" and d[0]["removed_in"] == "L3"
    assert "DB_PASSWORD" in d[0]["content"]


def test_secret_found_in_earlier_layer_not_in_final():
    s = lf.find_secrets(LEAKY)
    assert len(s) == 1 and s[0]["layer"] == "L2" and s[0]["in_final_image"] is False


def test_clean_image_has_no_leaks_and_no_dockle_findings():
    assert lf.deleted_but_present(CLEAN) == [] and lf.find_secrets(CLEAN) == []
    assert lf.dockle(CLEAN) == []


def test_efficiency_counts_overwritten_and_deleted_bytes():
    eff, wasted = lf.efficiency(LEAKY)
    assert wasted == 60 + 4000  # deleted .env + overwritten main.py
    assert eff < 100
    assert lf.efficiency(CLEAN) == (100.0, 0)


def test_dockle_ids_on_leaky_image():
    ids = {i for i, _, _ in lf.dockle(LEAKY)}
    assert {"CIS-DI-0001", "CIS-DI-0006", "CIS-DI-0008", "CIS-DI-0009", "CIS-DI-0010", "DKL-DI-0001", "DKL-DI-0005"} <= ids
    fatal = [i for i, l, _ in lf.dockle(LEAKY) if l == "FATAL"]
    assert fatal == ["CIS-DI-0010"]
