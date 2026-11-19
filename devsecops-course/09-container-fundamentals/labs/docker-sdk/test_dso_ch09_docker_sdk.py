from pathlib import Path

import pytest
from aisec_lab import load_lab_module

fd = load_lab_module(__file__, "fake_docker")
FIX = str(Path(__file__).parent / "fixtures" / "daemon-state.json")


def client():
    return fd.FakeDockerClient.from_fixture(FIX)


def test_list_running_vs_all():
    c = client()
    assert {x.name for x in c.containers.list()} == {"web", "agent"}
    assert {x.name for x in c.containers.list(all=True)} == {"web", "agent", "old-job"}


def test_list_filters():
    c = client()
    assert [x.name for x in c.containers.list(all=True, filters={"status": "exited"})] == ["old-job"]
    assert [x.name for x in c.containers.list(filters={"name": "we"})] == ["web"]


def test_pull_then_run():
    c = client()
    with pytest.raises(fd.ImageNotFound):
        c.containers.run("nginx:1.27", detach=True)          # not pulled yet
    c.images.pull("nginx", tag="1.27")
    box = c.containers.run("nginx:1.27", detach=True, name="n1", environment={"X": "1"})
    assert box.status == "running" and "X=1" in box.attrs["Config"]["Env"]


def test_pull_unknown_image_fails():
    with pytest.raises(fd.ImageNotFound):
        client().images.pull("evil/miner", tag="1")


def test_get_missing_container():
    with pytest.raises(fd.NotFound):
        client().containers.get("ghost")


def test_remove_running_needs_force():
    c = client()
    box = c.containers.get("web")
    with pytest.raises(RuntimeError):
        box.remove()
    box.remove(force=True)
    assert "web" not in {x.name for x in c.containers.list(all=True)}


def test_run_foreground_returns_logs_bytes():
    c = client()
    out = c.containers.run("alpine:3.20", "echo hi")
    assert isinstance(out, bytes) and b"echo hi" in out


def test_audit_finds_privileged_and_socket():
    f = fd.audit(client())
    assert "agent: privileged container" in f
    assert any("docker.sock" in x for x in f)
    assert "agent: unpinned image tools/agent:latest" in f
    assert not any(x.startswith("web:") for x in f)


def test_method_names_match_the_real_sdk():
    c = client()
    for attr in ("ping", "version", "info"):
        assert callable(getattr(c, attr))
    for attr in ("list", "run", "get"):
        assert callable(getattr(c.containers, attr))
    for attr in ("pull", "list", "get"):
        assert callable(getattr(c.images, attr))
