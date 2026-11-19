import pytest
from aisec_lab import load_lab_module

lc = load_lab_module(__file__, "lifecycle")


def test_run_is_create_plus_start():
    c = lc.run("a", "alpine")
    assert c.history == ["created", "running"]


def test_stop_then_start_again():
    c = lc.run("a", "alpine")
    c.do("stop")
    assert c.state == "exited"
    c.do("start")
    assert c.state == "running"


def test_cannot_remove_running_without_force():
    c = lc.run("a", "alpine")
    with pytest.raises(lc.LifecycleError):
        c.do("rm")
    c.do("rm -f")
    assert c.state == "removed"


def test_pause_unpause_roundtrip():
    c = lc.run("a", "alpine")
    c.do("pause")
    assert c.state == "paused"
    c.do("unpause")
    assert c.state == "running"


def test_every_task_maps_to_a_docker_command():
    assert all(v.startswith("docker ") for v in lc.COMMAND_FOR_TASK.values())
    assert len(lc.COMMAND_FOR_TASK) >= 10
