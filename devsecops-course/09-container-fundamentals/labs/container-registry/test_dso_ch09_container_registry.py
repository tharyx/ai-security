import pytest
from aisec_lab import load_lab_module

rs = load_lab_module(__file__, "registry_sim")


def test_ref_normalisation():
    r = rs.parse_ref("nginx")
    assert (r.registry, r.repo, r.tag) == ("docker.io", "library/nginx", "latest")
    r = rs.parse_ref("myuser/app:2.1")
    assert (r.registry, r.repo, r.tag) == ("docker.io", "myuser/app", "2.1")
    r = rs.parse_ref("localhost:5000/team/api:dev")
    assert (r.registry, r.repo, r.tag) == ("localhost:5000", "team/api", "dev")


def test_ref_with_digest_has_no_default_tag():
    r = rs.parse_ref("ghcr.io/o/t@sha256:" + "a" * 64)
    assert r.tag is None and r.digest.startswith("sha256:")


def test_push_pull_roundtrip_verifies_blobs():
    reg = rs.Registry()
    d = reg.push_image("a/b", "1", {"k": 1}, [b"x", b"y"])
    got = reg.pull("a/b:1")
    assert got["digest"] == d and got["verified"]


def test_same_content_same_digest():
    reg = rs.Registry()
    d1 = reg.push_image("a/b", "1", {"k": 1}, [b"x"])
    d2 = reg.push_image("a/b", "2", {"k": 1}, [b"x"])
    assert d1 == d2


def test_tag_moves_but_digest_does_not():
    reg = rs.Registry()
    d1 = reg.push_image("a/b", "1", {}, [b"x"])
    d2 = reg.push_image("a/b", "1", {}, [b"x", b"evil-canary"])
    assert d1 != d2
    assert reg.pull("a/b:1")["digest"] == d2
    assert reg.pull(f"a/b@{d1}")["digest"] == d1
    assert reg.untagged("a/b") == [d1]


def test_tag_command_shares_digest():
    reg = rs.Registry()
    d = reg.push_image("a/b", "1", {}, [b"x"])
    reg.tag("a/b", "1", "latest")
    assert reg.tags["a/b"]["latest"] == d
    assert reg.list_tags("a/b") == ["1", "latest"]


def test_delete_by_digest_removes_dangling_tags():
    reg = rs.Registry()
    d = reg.push_image("a/b", "1", {}, [b"x"])
    reg.tag("a/b", "1", "latest")
    reg.delete("a/b", d)
    assert reg.list_tags("a/b") == []
    with pytest.raises(KeyError):
        reg.pull("a/b:1")


def test_tampered_blob_detected():
    reg = rs.Registry()
    reg.push_image("a/b", "1", {}, [b"x"])
    d = next(iter(reg.manifests.values()))["layers"][0]
    reg.blobs[d] = b"tampered"
    assert reg.pull("a/b:1")["verified"] is False


def test_catalog():
    reg = rs.Registry()
    reg.push_image("z/z", "1", {}, [b"1"])
    reg.push_image("a/a", "1", {}, [b"2"])
    assert reg.catalog() == ["a/a", "z/z"]
