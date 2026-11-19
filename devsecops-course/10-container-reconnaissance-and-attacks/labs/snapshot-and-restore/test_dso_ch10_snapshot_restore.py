from aisec_lab import load_lab_module

sn = load_lab_module(__file__, "snapshots")


def make():
    base = sn.Image("web:1.0", [{"/app/app.py": "v1", "/etc/motd": "hi"}], {"env": ["A=1"]}, ["FROM scratch"])
    c = sn.Container(base, "c1")
    return base, c


def test_diff_added_changed_deleted():
    _, c = make()
    c.write("/new", "x")
    c.write("/app/app.py", "v2")
    c.delete("/etc/motd")
    assert c.diff() == {"/new": "A", "/app/app.py": "C", "/etc/motd": "D"}


def test_commit_adds_one_layer_and_keeps_history():
    base, c = make()
    c.write("/new", "x")
    img = c.commit("snap:1")
    assert len(img.layers) == len(base.layers) + 1
    assert img.history[-1] == "commit of c1" and img.config == base.config


def test_commit_records_deletions_but_old_layer_keeps_content():
    base, c = make()
    c.delete("/etc/motd")
    img = c.commit("snap:1")
    assert "/etc/motd" not in img.rootfs()
    assert img.layers[0]["/etc/motd"] == "hi"           # layers never forget


def test_restore_gives_a_copy_and_original_untouched():
    base, c = make()
    c.write("/evil", "canary")
    r = sn.restore(c.commit("snap:1"), "copy")
    assert r.fs["/evil"] == "canary"
    r.write("/evil", "changed")
    assert c.fs["/evil"] == "canary" and "/evil" not in base.rootfs()


def test_export_is_flat_and_loses_metadata():
    _, c = make()
    e = c.export()
    assert e["kind"] == "export" and "layers" not in e and "history" not in e


def test_save_keeps_layers_config_history():
    base, c = make()
    s = sn.save(c.commit("snap:1"))
    assert len(s["layers"]) == 2 and s["config"] and len(s["history"]) == 2


def test_snapshot_diff_between_times():
    d = sn.snapshot_diff({"a": "1", "b": "1"}, {"a": "2", "c": "1"})
    assert d == {"a": "modified", "b": "deleted", "c": "added"}


def test_compare_methods_table():
    _, c = make()
    m = sn.compare_methods(c)
    assert m["commit"]["keeps_history"] and not m["export"]["keeps_history"]
    assert not m["export"]["keeps_layers"] and m["save"]["keeps_layers"]
    assert not any(v["volumes_included"] for v in m.values())
