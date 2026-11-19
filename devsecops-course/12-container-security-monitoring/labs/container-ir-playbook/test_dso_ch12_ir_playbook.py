import copy
import json
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

ir = load_lab_module(__file__, "ir_playbook")
HERE = Path(__file__).parent
INC = json.loads((HERE / "fixtures" / "incident.json").read_text())
RB = ir.load_runbook(HERE / "runbook.yaml")


def _run(rb=RB, inc=INC):
    d = ir.FakeDocker(inc)
    with tempfile.TemporaryDirectory() as tmp:
        res = ir.run_playbook(rb, inc, d, Path(tmp) / "ev")
        files = sorted(p.name for p in (Path(tmp) / "ev").iterdir())
    return d, res, files


def idx(cmds, prefix):
    return next(i for i, c in enumerate(cmds) if c.startswith(prefix))


def test_order_preserve_snapshot_isolate_collect_redeploy():
    _, res, _ = _run()
    c = res["commands"]
    assert idx(c, "docker inspect") < idx(c, "docker commit") < idx(c, "docker pause") < idx(c, "ss -tnp") < idx(c, "docker stop") < idx(c, "docker run")


def test_every_network_disconnected_before_stop():
    d, res, _ = _run()
    assert d.networks == [] and sum(c.startswith("docker network disconnect") for c in res["commands"]) == 2


def test_evidence_manifest_hashes_and_files():
    _, res, files = _run()
    assert {"inspect.json", "container.log", "rootfs.tar", "MANIFEST.sha256"} <= set(files)
    assert all(len(h) == 64 for h in res["manifest"].values())


def test_destructive_step_refused_without_snapshot():
    rb = copy.deepcopy(RB)
    rb["phases"] = [p for p in rb["phases"] if p["phase"] != "snapshot"]
    with pytest.raises(ir.PlaybookError, match="evidence not preserved"):
        _run(rb)


def test_destructive_step_refused_while_attached():
    rb = copy.deepcopy(RB)
    rb["phases"] = [p for p in rb["phases"] if p["phase"] != "isolate"]
    with pytest.raises(ir.PlaybookError, match="still attached"):
        _run(rb)


def test_same_digest_redeploy_refused():
    bad = dict(INC, clean_image_digest=INC["image_digest"])
    with pytest.raises(ir.PlaybookError, match="compromised image digest"):
        _run(inc=bad)
