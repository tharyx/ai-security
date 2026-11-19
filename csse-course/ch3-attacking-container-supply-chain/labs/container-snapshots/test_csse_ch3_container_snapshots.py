import json
from pathlib import Path

from aisec_lab import load_lab_module

sn = load_lab_module(__file__, "snapshot")
FIX = Path(__file__).parent / "fixtures"
BASE = json.loads((FIX / "base_layers.json").read_text())["layers"]
CHANGES = json.loads((FIX / "container_changes.json").read_text())["files"]


def test_save_load_round_trip():
    img = sn.load(sn.save(BASE, "shop-api:1.0"))
    assert img.repo_tags == ["shop-api:1.0"]
    assert sn.flatten(img.layers)["/srv/app/main.py"] == "print('shop api')"


def test_layer_digests_are_reproducible():
    assert sn.load(sn.save(BASE, "a:1")).diff_ids == sn.load(sn.save(BASE, "b:2")).diff_ids


def test_commit_adds_one_layer_and_keeps_lower_digests():
    v1 = sn.load(sn.save(BASE, "x:1"))
    v2 = sn.load(sn.save(sn.commit(BASE, CHANGES), "x:2"))
    assert len(v2.layers) == len(v1.layers) + 1
    assert v2.diff_ids[:2] == v1.diff_ids


def test_diff_finds_added_modified_removed():
    after = sn.flatten(sn.commit(BASE, CHANGES))
    d = sn.diff(sn.flatten(BASE), after)
    assert "/usr/local/bin/healthcheck.sh" in d["added"] and "/etc/cron.d/refresh" in d["added"]
    assert d["modified"] == ["/srv/app/config.yaml"]
    assert d["removed"] == ["/etc/passwd"]


def test_whiteout_survives_the_tar_round_trip():
    img = sn.load(sn.save(sn.commit(BASE, CHANGES), "x:2"))
    assert img.layers[-1]["/etc/passwd"] is None


def test_suspicious_paths_flagged_but_notes_are_not():
    d = sn.diff(sn.flatten(BASE), sn.flatten(sn.commit(BASE, CHANGES)))
    flagged = sn.suspicious(d["added"])
    assert "/etc/cron.d/refresh" in flagged and "/srv/app/notes.txt" not in flagged


def test_deleted_secret_still_exists_in_lower_layer():
    layers = [{"created_by": "COPY .env", "files": {"/app/.env": "TOKEN=FAKE"}},
              {"created_by": "RUN rm .env", "files": {"/app/.env": None}}]
    img = sn.load(sn.save(layers, "leaky:1"))
    assert "/app/.env" not in sn.flatten(img.layers)      # the running container does not see it
    assert img.layers[0]["/app/.env"] == "TOKEN=FAKE"     # but the layer tar still holds it
