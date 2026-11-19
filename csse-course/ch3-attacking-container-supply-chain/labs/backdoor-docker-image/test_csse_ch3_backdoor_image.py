import copy
import json
from pathlib import Path

from aisec_lab import load_lab_module

v = load_lab_module(__file__, "verify")
FIX = Path(__file__).parent / "fixtures"
ORIG = json.loads((FIX / "original.json").read_text())
BAD = json.loads((FIX / "backdoored.json").read_text())


def test_digest_is_stable_and_content_sensitive():
    assert v.image_digest(ORIG) == v.image_digest(copy.deepcopy(ORIG))
    assert v.image_digest(ORIG) != v.image_digest(BAD)


def test_lower_layers_keep_their_digest():
    assert v.layer_digest(ORIG["layers"][0]) == v.layer_digest(BAD["layers"][0])


def test_diff_finds_extra_layer_and_files():
    d = v.diff_images(ORIG, BAD)
    assert d.added_layers == [2] and d.changed_layers == []
    assert "/etc/profile.d/zz-update.sh" in d.added_files
    assert set(v.autorun_additions(d)) == {"/etc/profile.d/zz-update.sh", "/docker-entrypoint.d/10-warmup.sh"}


def test_canary_detection_and_clean_image():
    assert [p for _, p in v.find_canaries(BAD)] == ["/etc/profile.d/zz-update.sh", "/docker-entrypoint.d/10-warmup.sh"]
    assert v.find_canaries(ORIG) == []


def test_modifying_an_existing_layer_is_a_changed_layer():
    tampered = copy.deepcopy(ORIG)
    tampered["layers"][1]["files"]["/usr/local/bin/server"] = "SERVER-BINARY-v1.0-TAMPERED"
    d = v.diff_images(ORIG, tampered)
    assert d.changed_layers == [1] and d.modified_files == ["/usr/local/bin/server"]


def test_tag_re_push_is_caught_by_digest_pin_only():
    store = v.TagStore()
    pins = {"shop-api:1.0": store.push("shop-api:1.0", ORIG)}
    store.push("shop-api:1.0", BAD)
    ok, reason = v.verify_pin("shop-api:1.0", store.pull_by_tag("shop-api:1.0"), pins)
    assert not ok and "mismatch" in reason


def test_matching_pin_passes_and_unpinned_is_refused():
    pins = {"shop-api:1.0": v.image_digest(ORIG)}
    assert v.verify_pin("shop-api:1.0", ORIG, pins)[0]
    ok, reason = v.verify_pin("other:1", ORIG, pins)
    assert not ok and "no pinned digest" in reason


def test_config_change_alone_changes_digest():
    cfg = copy.deepcopy(ORIG)
    cfg["config"]["Entrypoint"] = ["/bin/sh", "-c", "echo canary"]
    assert v.diff_images(ORIG, cfg).config_changed and v.image_digest(cfg) != v.image_digest(ORIG)
