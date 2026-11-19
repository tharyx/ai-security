import csv
import io
import json
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

ac = load_lab_module(__file__, "asvs_checklist")
FIX = Path(__file__).resolve().parent / "fixtures"
REQS = ac.load_sample(FIX / "asvs5_sample.json")
SHOP = json.loads((FIX / "profile_shop.json").read_text(encoding="utf-8"))
RESULTS = json.loads((FIX / "results_shop.json").read_text(encoding="utf-8"))


def ids(items):
    return {i["id"] for i in items}


def test_level_filter_excludes_higher_levels():
    l1 = ac.select(REQS, 1, ["web", "api", "cookies", "passwords"])
    assert all(i["level"] == 1 for i in l1)
    assert "APS-V16-S2" not in ids(ac.select(REQS, 2, ["web"]))  # L3 item
    assert "APS-V16-S2" in ids(ac.select(REQS, 3, ["web"]))


def test_feature_filter_drops_requirements_for_absent_features():
    shop = ids(ac.select(REQS, SHOP["level"], SHOP["features"]))
    assert "APS-V5-S1" not in shop        # no file upload
    assert "APS-V10-S1" not in shop       # no OAuth
    assert "APS-V8-S1" in shop            # 'all' items always apply


def test_api_profile_gets_token_and_oauth_items_but_not_cookie_items():
    api = ids(ac.select(REQS, 1, ["api", "tokens", "oauth"]))
    assert {"APS-V9-S1", "APS-V10-S1", "APS-V7-S1"} <= api
    assert "APS-V3-S1" not in api


def test_internal_ids_are_stable_and_map_to_the_asvs_ref():
    a = ac.select(REQS, 1, ["api"])
    b = ac.select(REQS, 3, ["web", "api", "files"])
    common = ids(a) & ids(b)
    for i in a:
        if i["id"] in common:
            assert next(x for x in b if x["id"] == i["id"])["ref"] == i["ref"]
    assert ac.internal_id("V10.S1") == "APS-V10-S1"


def test_items_are_ordered_by_chapter_number_not_text():
    chapters = [i["chapter"] for i in ac.select(REQS, 3, ["web", "api", "cookies", "passwords"])]
    assert chapters.index("V2") < chapters.index("V11") < chapters.index("V16")


def test_invalid_level_rejected():
    with pytest.raises(ValueError):
        ac.select(REQS, 4, ["web"])


def test_results_summary_and_gate_fail_for_shop():
    items = ac.apply_results(ac.select(REQS, SHOP["level"], SHOP["features"]), RESULTS)
    s = ac.summary(items)
    assert s["total"] == 23 and s["fail"] == 3 and s["untested"] == 3
    assert ac.gate(items) == 1


def test_gate_passes_when_everything_applicable_passes_or_is_na():
    items = ac.select(REQS, 1, ["api"])
    res = {i["id"]: {"status": "pass"} for i in items}
    res[items[0]["id"]] = {"status": "na"}
    assert ac.gate(ac.apply_results(items, res)) == 0


def test_untested_level1_item_fails_gate_but_untested_level2_does_not():
    items = [i for i in ac.select(REQS, 2, ["web"]) if i["id"] in ("APS-V1-S2", "APS-V3-S2")]
    l2_only = ac.apply_results(items, {"APS-V1-S2": {"status": "pass"}})
    assert ac.gate(l2_only) == 0
    assert ac.gate(ac.apply_results(items, {})) == 1


def test_unknown_status_is_an_error():
    with pytest.raises(ValueError):
        ac.apply_results(ac.select(REQS, 1, ["api"]), {"APS-V1-S1": {"status": "done"}})


def test_markdown_and_csv_outputs():
    items = ac.apply_results(ac.select(REQS, SHOP["level"], SHOP["features"]), RESULTS)
    md = ac.to_markdown(items, "shop")
    assert "## V8 Authorization" in md and "[ ] FAIL **APS-V6-S2**" in md
    rows = list(csv.DictReader(io.StringIO(ac.to_csv(items))))
    assert len(rows) == 23 and rows[0]["asvs_ref"] == "V1.S1"


def test_csv_loader_reads_an_official_style_export():
    reqs = ac.load_csv(FIX / "official_like.csv")
    assert [r["ref"] for r in reqs] == ["SAMPLE-1.2.1", "SAMPLE-8.2.1", "SAMPLE-16.4.1"]
    assert [i["id"] for i in ac.select(reqs, 1, ["web"])] == ["APS-SAMPLE-1-2-1", "APS-SAMPLE-8-2-1"]
