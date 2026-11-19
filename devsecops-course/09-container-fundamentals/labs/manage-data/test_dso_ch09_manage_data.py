import pytest
from aisec_lab import load_lab_module

ds = load_lab_module(__file__, "datastore")


def test_parse_kinds():
    assert ds.parse_v("data:/d").kind == "volume"
    assert ds.parse_v("/srv/x:/d").kind == "bind"
    assert ds.parse_v("/d").kind == "anonymous"
    assert ds.parse_v("/srv/x:/d:ro").read_only


def test_persistence_after_rm():
    h = ds.Host()
    c = h.run([ds.parse_v("v:/data"), ds.Mount("tmpfs", "", "/run/s")])
    assert c.write("/data/a", "1") == "volume v"
    c.write("/run/s/t", "2")
    c.write("/tmp/x", "3")
    c.rm()
    assert h.volumes["v"] == {"/data/a": "1"}
    assert c.tmpfs == {} and c.layer == {}


def test_bind_mount_writes_to_host():
    h = ds.Host()
    c = h.run([ds.parse_v("/srv/app-config:/etc/app")])
    c.write("/etc/app/app.conf", "pwned=canary")
    assert h.host_fs["/srv/app-config/app.conf"] == "pwned=canary"


def test_read_only_blocks_write():
    h = ds.Host()
    c = h.run([ds.parse_v("/srv/a:/a:ro")])
    with pytest.raises(PermissionError):
        c.write("/a/f", "x")


def test_docker_socket_and_root_are_critical():
    assert ds.risks(ds.parse_v("/var/run/docker.sock:/var/run/docker.sock"))[0][0] == "CRITICAL"
    assert ds.risks(ds.parse_v("/:/host"))[0][0] == "CRITICAL"
    assert ds.risks(ds.parse_v("/etc/ssh:/ssh"))[0][1].startswith("bind mount of /etc/ssh exposes host configuration")


def test_read_only_and_plain_volume_ok_or_lower():
    assert ds.risks(ds.parse_v("/srv/app:/app:ro")) == []
    assert ds.risks(ds.parse_v("dbdata:/db")) == []
    assert ds.risks(ds.parse_v("/srv/app:/app"))[0][0] == "MEDIUM"


def test_anonymous_volume_low():
    assert ds.risks(ds.parse_v("/data"))[0][0] == "LOW"
