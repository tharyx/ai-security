import pytest

from aisec_lab import load_lab_module

t = load_lab_module(__file__, "top10")
RESULTS = {item: (v, s) for item, v, s in t.run_all()}


def test_mapping_covers_all_ten_2019_items_and_three_new_2023_items():
    assert len(t.MAP_2019_TO_2023) == 10 and len(t.NEW_IN_2023) == 3
    mapped = {v for v in t.MAP_2019_TO_2023.values() if v} | set(t.NEW_IN_2023)
    assert len(mapped) == 10  # the ten 2023 items


def test_excessive_data_exposure_and_mass_assignment_merge_into_bopla():
    assert t.MAP_2019_TO_2023["API3:2019 Excessive Data Exposure"] == t.MAP_2019_TO_2023["API6:2019 Mass Assignment"]
    assert t.MAP_2019_TO_2023["API8:2019 Injection"] is None
    assert t.MAP_2019_TO_2023["API10:2019 Insufficient Logging & Monitoring"] is None


@pytest.mark.parametrize("item", list(RESULTS))
def test_attack_works_on_vulnerable_and_fails_on_secure(item):
    vuln, sec = RESULTS[item]
    assert vuln is True and sec is False


def test_resource_limit_caps_page_size():
    assert len(t.api4_list(True, 10**6)) == 100


def test_inventory_diff_lists_zombie_v1_and_debug_endpoints():
    assert t.api9_undocumented(t.DEPLOYED_VULN) == ["GET /api/v1/users/{id}", "GET /api/v2/debug/env", "POST /api/v1/login"]


def test_unsafe_consumption_secure_version_rejects_upstream_payload():
    assert t.api10_consume(True, "560001")[0].startswith("rejected")
