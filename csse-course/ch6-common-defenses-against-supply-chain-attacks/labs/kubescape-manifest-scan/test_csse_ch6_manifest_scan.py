"""Tests for the Kubescape-style manifest controls."""

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "manifest_scan")


def ids(text, fw="all"):
    return {c for c, _, _ in m.scan(text, fw)}


def test_bad_deployment_fails_key_controls():
    assert {"KL-01", "KL-02", "KL-03", "KL-05", "KL-07", "KL-08", "KL-09"} <= ids(m.BAD)


def test_good_deployment_passes_everything():
    assert m.scan(m.GOOD) == []
    assert m.compliance_score([]) == 100


def test_digest_pinned_image_is_not_mutable():
    assert "KL-08" not in ids(m.GOOD) and "KL-08" in ids(m.BAD)


def test_pod_level_run_as_non_root_counts():
    assert "KL-03" not in ids(m.GOOD)


def test_framework_selection_limits_controls():
    assert ids(m.BAD, "supply-chain") == {"KL-08", "KL-09"}
    assert "KL-01" not in ids(m.BAD, "supply-chain")


def test_exceptions_suppress_specific_control_on_specific_workload():
    f = m.scan(m.BAD, exceptions={("KL-02", "Deployment/web")})
    assert "KL-02" not in {c for c, _, _ in f}


def test_compliance_score_drops_with_failures():
    assert m.compliance_score(m.scan(m.BAD)) < 50


def test_cronjob_and_pod_shapes_supported():
    pod = {"kind": "Pod", "metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "image": "x"}]}}
    cj = {"kind": "CronJob", "metadata": {"name": "j"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "c", "image": "x:1"}]}}}}}}
    assert m.check_doc(pod) and m.check_doc(cj)
    assert m.check_doc({"kind": "ConfigMap", "metadata": {"name": "c"}}) == []


def test_hostpath_detected():
    d = {"kind": "Pod", "metadata": {"name": "p"}, "spec": {"volumes": [{"name": "h", "hostPath": {"path": "/"}}], "containers": []}}
    assert ("KL-11", "Pod/p", "pod") in m.check_doc(d)
