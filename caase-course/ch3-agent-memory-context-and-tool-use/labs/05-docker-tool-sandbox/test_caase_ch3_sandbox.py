"""Docker sandbox policy generator (no Docker needed) and the subprocess sandbox twin."""

import os

import pytest

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "sandbox")


# ---- policy generator --------------------------------------------------------------
def test_default_policy_generates_the_hardened_command():
    args = s.build_docker_args(s.SandboxPolicy())
    joined = " ".join(args)
    assert args[:3] == ["docker", "run", "--rm"]
    for needle in ("--network none", "--read-only", "--user 10001:10001", "--cap-drop ALL",
                   "--security-opt no-new-privileges", "--memory 256m", "--cpus 0.5", "--pids-limit 64",
                   "--tmpfs /tmp:rw,noexec,nosuid,size=16m"):
        assert needle in joined
    assert args[-3:] == ["agent-tool-sandbox:1.0", "python", "/app/tool.py"]


def test_read_only_mount_is_rendered():
    p = s.SandboxPolicy(mounts=(("/srv/work/in", "/data", "ro"),))
    assert "-v /srv/work/in:/data:ro" in " ".join(s.build_docker_args(p, allowed_host_roots=("/srv/work",)))


@pytest.mark.parametrize("kw, message", [
    ({"network": "bridge"}, "network"),
    ({"read_only": False}, "read-only"),
    ({"user": "root"}, "non-root"),
    ({"user": "0:0"}, "non-root"),
    ({"cap_drop": ("NET_RAW",)}, "ALL capabilities"),
    ({"no_new_privileges": False}, "no-new-privileges"),
    ({"memory": ""}, "limits"),
    ({"pids_limit": 0}, "limits"),
    ({"privileged": True}, "privileged"),
    ({"image": "tool:latest"}, "pinned"),
    ({"image": "tool"}, "pinned"),
    ({"mounts": (("/var/run/docker.sock", "/var/run/docker.sock", "ro"),)}, "sensitive host path"),
    ({"mounts": (("/srv/work", "/data", "rw"),)}, "read-only"),
    ({"mounts": (("/home/alice", "/data", "ro"),)}, "outside allowed roots"),
    ({"env": (("API_TOKEN", "x"),)}, "secret-looking"),
])
def test_unsafe_policies_are_refused_and_no_command_is_built(kw, message):
    p = s.SandboxPolicy(**kw)
    assert any(message in x for x in s.validate_policy(p, allowed_host_roots=("/srv/work",)))
    with pytest.raises(s.PolicyError):
        s.build_docker_args(p, allowed_host_roots=("/srv/work",))


def test_digest_pinned_image_is_accepted():
    p = s.SandboxPolicy(image="registry.example/tool@sha256:" + "a" * 64)
    assert s.validate_policy(p) == []


# ---- subprocess twin ---------------------------------------------------------------
def test_sandboxed_code_runs_and_returns_output():
    r = s.SubprocessSandbox().run_python("print(6*7)")
    assert r.returncode == 0 and r.stdout.strip() == "42"


def test_environment_secrets_are_not_visible_inside():
    os.environ["CAASE_FAKE_SECRET_TOKEN"] = "FAKE-TOKEN-123"
    try:
        code = "import os; print(os.environ.get('CAASE_FAKE_SECRET_TOKEN'))"
        assert s.SubprocessSandbox().run_python(code).stdout.strip() == "None"
        assert s.SubprocessSandbox(scrub_env=False).run_python(code).stdout.strip() == "FAKE-TOKEN-123"
    finally:
        del os.environ["CAASE_FAKE_SECRET_TOKEN"]


def test_runaway_code_is_killed_by_the_timeout():
    box = s.SubprocessSandbox(timeout_s=0.5)
    r = box.run_python("while True: pass")
    assert r.timed_out and box.log == ["timeout-killed"]


def test_output_is_capped():
    box = s.SubprocessSandbox(max_output=100)
    r = box.run_python("print('x' * 10000)")
    assert r.truncated and len(r.stdout) == 100 and box.log == ["output-truncated"]


def test_working_directory_is_private_and_temporary():
    r = s.SubprocessSandbox().run_python("import os; print(os.getcwd())")
    assert not os.path.exists(r.stdout.strip())  # deleted after the run


def test_twin_is_not_isolation_it_cannot_stop_file_reads():
    # honest limit: a subprocess can still read files the user can read. That is why the real boundary is a container.
    r = s.SubprocessSandbox().run_python(f"print(open({__file__!r}).read()[:6])")
    assert r.returncode == 0 and r.stdout.strip() == '"""Doc'
