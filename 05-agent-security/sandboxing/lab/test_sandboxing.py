"""Regression tests: what the denylist-only runner lets through, and what the sandbox holds.

Run from the repository root (takes about 10 seconds - some tests wait for timeouts):
    python -m pytest 05-agent-security/sandboxing -v
"""

import os
import shutil
import tempfile
import threading
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

attacks = load_lab_module(__file__, "attacks")
vuln = load_lab_module(__file__, "vulnerable_runner")
sec = load_lab_module(__file__, "secure_runner")

S = attacks.SNIPPETS
SECRETS = (attacks.ENV_CANARY, attacks.DOTENV_CANARY)


@pytest.fixture
def scratch():
    """A throw-away folder that is NOT the sandbox work dir (plain tempfile)."""
    path = Path(tempfile.mkdtemp(prefix="aisec-05-"))
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def project(scratch):
    """The agent's own project folder, with a secret in .env."""
    (scratch / ".env").write_text(f"ACME_API_KEY={attacks.DOTENV_CANARY}\n", encoding="utf-8")
    return scratch


@pytest.fixture
def host_env():
    return {**os.environ, "ACME_API_KEY": attacks.ENV_CANARY}


def sandbox(host_env, **kw):
    kw.setdefault("timeout", 1.0)
    return sec.SubprocessSandbox(host_env=host_env, **kw)


def leaked(text: str) -> bool:
    return any(s in text for s in SECRETS)


# ---------- Part 1: the denylist is a soft layer -------------------------------------

def test_denylist_catches_the_obvious_snippet():
    assert vuln.denylist_problem(S["read_env_obvious"]) == "import of os"


@pytest.mark.parametrize("name", ["read_env_bypass", "read_project_dotenv", "write_outside_workdir",
                                  "spawn_process"])
def test_denylist_misses_runtime_built_names(name):
    assert vuln.denylist_problem(S[name]) is None


def test_bypass_steals_env_secret_from_naive_runner(project, host_env):
    res = vuln.NaiveRunner(str(project), host_env).run(S["read_env_bypass"])
    assert attacks.ENV_CANARY in res.stdout


def test_bypass_reads_project_dotenv_from_naive_runner(project, host_env):
    res = vuln.NaiveRunner(str(project), host_env).run(S["read_project_dotenv"])
    assert attacks.DOTENV_CANARY in res.stdout


def test_naive_runner_writes_outside_and_hangs(project, host_env):
    target = project / "PWNED.txt"
    vuln.NaiveRunner(str(project), host_env).run(S["write_outside_workdir"].replace("{target}", str(target)))
    assert target.exists()
    assert vuln.NaiveRunner(str(project), host_env, lab_fuse=1.0).run(S["infinite_loop"]).status == "hung"


# ---------- Part 2: the sandbox holds --------------------------------------------------

@pytest.mark.parametrize("name", list(S))
def test_no_secret_leaks_from_any_snippet(name, host_env, scratch):
    target = scratch / "PWNED.txt"
    res = sandbox(host_env).run(S[name].replace("{target}", str(target)))
    assert not leaked(res.stdout)
    assert not target.exists()


def test_env_is_scrubbed_even_though_the_bypass_runs(host_env):
    res = sandbox(host_env).run(S["read_env_bypass"])
    assert res.status == "ok"  # the code ran ...
    assert res.stdout.strip() == "no secret here"  # ... but there was nothing to steal


def test_work_dir_is_empty_and_temporary(host_env):
    res = sandbox(host_env).run(S["read_project_dotenv"])
    assert res.status == "error" and "FileNotFoundError" in res.stdout
    own = sandbox(host_env).run(attacks.WRITE_OWN_FILE)
    assert own.files == ["out.txt"]
    assert not os.path.exists(own.workdir)  # rollback by design: nothing persists


def test_timeout_kills_infinite_loop(host_env):
    res = sandbox(host_env, timeout=1.0).run(S["infinite_loop"])
    assert res.status == "timeout"
    assert res.seconds < 5


def test_output_is_capped(host_env):
    res = sandbox(host_env, max_output=10_000).run(S["huge_output"])
    assert res.status == "output_capped"
    assert len(res.stdout) <= 10_000


def test_guard_blocks_write_outside_and_new_processes(host_env, scratch):
    target = scratch / "PWNED.txt"
    res = sandbox(host_env).run(S["write_outside_workdir"].replace("{target}", str(target)))
    assert res.status == "blocked" and not target.exists()
    res = sandbox(host_env).run(S["spawn_process"])
    assert res.status == "blocked" and "b'42" not in res.stdout


def test_guard_blocks_network(host_env):
    res = sandbox(host_env).run(attacks.NETWORK_SNIPPET)
    assert res.status == "blocked" and "network access blocked" in res.events[0]


def test_child_runs_in_isolated_mode(host_env):
    code = "s = getattr(__builtins__, '__imp' + 'ort__')('s' + 'ys')\nprint(s.flags.isolated)"
    assert sandbox(host_env).run(code).stdout.strip() == "1"


# ---------- Part 3: hard layers hold with the soft layers off --------------------------

def test_hard_layers_alone_protect_secrets(host_env):
    box = sandbox(host_env, denylist=False, fs_guard=False, block_network=False)
    for name in ("read_env_obvious", "read_env_bypass", "read_project_dotenv"):
        assert not leaked(box.run(S[name]).stdout), name


def test_without_env_scrubbing_the_secret_leaks(host_env):
    box = sandbox(host_env, denylist=False, scrub_env=False)
    assert attacks.ENV_CANARY in box.run(S["read_env_obvious"]).stdout


def test_honest_gap_process_boundary_alone_does_not_stop_absolute_path_writes(host_env, scratch):
    """Without the (soft) guard, a subprocess can write anywhere the OS user can.

    This is why production sandboxes add a filesystem boundary: a container with a
    read-only root and no host mounts, gVisor, or a microVM.
    """
    target = scratch / "PWNED.txt"
    sandbox(host_env, fs_guard=False).run(S["write_outside_workdir"].replace("{target}", str(target)))
    assert target.exists()


# ---------- Part 4: kill switch ----------------------------------------------------------

def test_kill_switch_stops_running_code_and_refuses_new_runs(host_env):
    switch = sec.KillSwitch()
    box = sandbox(host_env, timeout=30, kill_switch=switch)
    threading.Timer(0.5, switch.trip, args=("test",)).start()
    running = box.run(S["infinite_loop"])
    assert running.status == "killed" and running.seconds < 10
    assert box.run(attacks.BENIGN).status == "refused"
    switch.reset()
    assert box.run(attacks.BENIGN).status == "ok"


# ---------- Part 5: benign path ----------------------------------------------------------

def test_benign_snippet_works(host_env):
    res = sandbox(host_env).run(attacks.BENIGN)
    assert res.status == "ok" and res.stdout.strip() == "total 29" and res.events == []
