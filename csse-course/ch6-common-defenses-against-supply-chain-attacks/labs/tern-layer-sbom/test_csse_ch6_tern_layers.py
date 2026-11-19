"""Tests for the layer-by-layer SBOM."""

from aisec_lab import load_lab_module

t = load_lab_module(__file__, "layer_sbom")


def test_first_layer_adds_base_packages():
    r = t.layer_deltas(t.IMAGE)[0]
    assert set(r["added"]) == {"libc6", "bash"} and r["base"]


def test_second_layer_attributed_to_apt_install():
    r = t.layer_deltas(t.IMAGE)[1]
    assert set(r["added"]) == {"curl", "openssl"} and "apt-get install" in r["created_by"]


def test_upgrade_and_removal_in_third_layer():
    r = t.layer_deltas(t.IMAGE)[2]
    assert r["changed"]["openssl"] == ("3.0.13-1~deb12u1", "3.0.14-1~deb12u1") and "curl" in r["removed"]


def test_final_attribution_points_to_latest_layer_for_upgraded_package():
    a = t.attribution(t.IMAGE)
    assert a["openssl"]["layer"] == "sha256:l3" and a["libc6"]["layer"] == "sha256:l1"
    assert "curl" not in a


def test_base_vs_added():
    b = t.base_vs_added(t.IMAGE)
    assert b["from_base_image"] == ["bash", "libc6"] and b["added_by_you"] == ["openssl"]


def test_copy_layer_changes_no_packages():
    assert t.layers_without_packages(t.IMAGE) == ["sha256:l4"]


def test_removed_package_still_in_history():
    assert t.deleted_but_present_in_history(t.IMAGE) == ["curl"]
