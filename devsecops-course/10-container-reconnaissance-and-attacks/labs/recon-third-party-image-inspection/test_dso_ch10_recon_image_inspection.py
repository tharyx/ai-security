from aisec_lab import load_lab_module

ls = load_lab_module(__file__, "layerscan")
IMG = ls.sample_image()


def test_whiteout_removes_file_from_final_view():
    fs = ls.effective_fs(IMG)
    assert "/app/secrets/id_key" not in fs
    assert "/var/lib/apt/lists/pkg" not in fs
    assert "/app/.env" in fs


def test_overwritten_file_uses_latest_layer():
    fs = ls.effective_fs(IMG)
    assert fs["/app/data.bin"] == (8_500_000, 5)


def test_efficiency_counts_overwritten_and_deleted_bytes():
    e = ls.efficiency(IMG)
    # apt lists (25 MB, deleted), the key (200 B, deleted) and the old data.bin (8 MB, overwritten)
    assert e["wasted"] == 25_000_000 + 200 + 8_000_000
    assert 0.5 < e["score"] < 1.0
    assert e["total"] == e["visible"] + e["wasted"]


def test_secrets_found_even_after_deletion():
    found = {s["path"]: s for s in ls.find_secrets(IMG)}
    assert found["/app/secrets/id_key"]["still_visible"] is False
    assert found["/app/secrets/id_key"]["kind"] == "private key block"
    assert found["/app/.env"]["still_visible"] is True


def test_no_literal_key_or_token_in_source():
    src = open(ls.__file__, encoding="utf-8").read()
    assert "-----BEGIN FAKE" not in src
    assert "dso-fake-token-c0ffee12" not in src


def test_vuln_matching_respects_fixed_version():
    hits = {h["package"]: h for h in ls.vulnerable_packages(IMG)}
    assert set(hits) == {"openssl", "libwebp"}               # curl 8.9.1 is already fixed
    assert ls.vulnerable_packages(IMG)[0]["severity"] == "CRITICAL"


def test_clean_image_has_perfect_efficiency():
    clean = {"name": "x", "layers": [{"created_by": "COPY a /a", "files": {"/a": {"size": 10}}}], "packages": []}
    assert ls.efficiency(clean)["score"] == 1.0
    assert ls.find_secrets(clean) == []
