"""Tests: count workspace escapes in a standard vs an isolated runtime (temp dirs only)."""

import pytest

from aisec_lab import load_lab_module

r = load_lab_module(__file__, "runtimes")


@pytest.fixture
def layout():
    lay = r.Layout()
    yield lay
    lay.close()


def test_normal_files_work_in_both_runtimes(layout):
    for rt in (r.StandardRuntime(layout.work), r.IsolatedRuntime(layout.work)):
        assert rt.read("ok.txt") == "normal project file"
        assert rt.read("sub/deep.txt") == "deep project file"


def test_standard_runtime_leaks_through_several_techniques(layout):
    res = r.run_attacks(layout, r.StandardRuntime(layout.work))
    escapes, _ = r.count(res)
    assert escapes >= 5
    for name in ("dotdot", "nested-dotdot", "prefix-sibling", "absolute-prefix-sibling", "shell-cd-dotdot"):
        assert res[name] == "ESCAPED", name


def test_standard_prefix_check_does_block_plain_absolute_paths(layout):
    res = r.run_attacks(layout, r.StandardRuntime(layout.work))
    assert res["absolute-path"] == "blocked" and res["shell-absolute-cat"] == "blocked"


def test_isolated_runtime_has_zero_escapes(layout):
    rt = r.IsolatedRuntime(layout.work)
    res = r.run_attacks(layout, rt)
    escapes, blocked = r.count(res)
    assert escapes == 0
    assert blocked >= 7
    assert any(a.startswith("DENY escape") for a in rt.audit)


def test_symlink_escape_standard_vs_isolated(layout):
    if not layout.symlink_ok:
        pytest.skip("this OS/user cannot create symlinks")
    assert r.run_attacks(layout, r.StandardRuntime(layout.work))["symlink"] == "ESCAPED"
    assert r.run_attacks(layout, r.IsolatedRuntime(layout.work))["symlink"] == "blocked"


def test_isolated_treats_absolute_paths_as_inside_the_root(layout):
    rt = r.IsolatedRuntime(layout.work)
    assert rt.read(str(layout.outside / "secret.txt")) == ""      # re-rooted, so nothing there
    assert rt.read("/ok.txt") == "normal project file"             # "/" is the workspace root


def test_policy_blocks_sensitive_names_even_inside_the_workspace(layout):
    assert r.StandardRuntime(layout.work).read(".env").startswith("FAKE_KEY")
    with pytest.raises(r.Denied):
        r.IsolatedRuntime(layout.work).read(".env")


def test_size_limit_policy(layout):
    (layout.work / "big.txt").write_text("x" * 200)
    rt = r.IsolatedRuntime(layout.work, r.Policy(max_bytes=100))
    with pytest.raises(r.Denied):
        rt.read("big.txt")


def test_shell_cd_inside_workspace_still_allowed(layout):
    rt = r.IsolatedRuntime(layout.work)
    assert rt.shell("cd sub && cat deep.txt") == "deep project file"


def test_defence_in_depth_note_container_is_not_a_substitute_for_least_privilege(layout):
    # the isolated runtime can still read everything INSIDE the workspace
    rt = r.IsolatedRuntime(layout.work, r.Policy(deny_globs=()))
    assert rt.read(".env").startswith("FAKE_KEY")
