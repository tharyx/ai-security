import copy
from pathlib import Path

import yaml
from aisec_lab import load_lab_module

pe = load_lab_module(__file__, "pod_escape")
PATH = Path(__file__).parent / "fixtures/pods.yaml"
RESULT = pe.analyse_file(PATH)
PODS = {d["metadata"]["name"]: d for d in yaml.safe_load_all(PATH.read_text())}


def spec(name):
    return copy.deepcopy(PODS[name]["spec"])


def test_privileged_pod_is_level_privileged_with_escape_paths():
    r = RESULT["Pod/debug-priv"]
    assert r["level"] == "privileged" and {"privileged", "hostPath", "hostPID+ptrace"} <= set(r["escapes"])


def test_log_collector_hostpath_breaks_baseline_but_is_a_narrow_mount():
    r = RESULT["Pod/log-collector"]
    assert r["level"] == "privileged" and r["escapes"] == ["hostPath-narrow"]


def test_default_pod_is_baseline_not_restricted():
    r = RESULT["Pod/web-baseline"]
    assert r["level"] == "baseline" and r["escapes"] == [] and r["restricted"]


def test_hardened_pod_is_restricted():
    assert RESULT["Pod/web-restricted"]["level"] == "restricted"


def test_each_restricted_requirement_matters():
    base = spec("web-restricted")
    for mutate in (lambda s: s["containers"][0]["securityContext"].pop("allowPrivilegeEscalation"),
                   lambda s: s["containers"][0]["securityContext"].pop("capabilities"),
                   lambda s: s["securityContext"].pop("seccompProfile"),
                   lambda s: s["securityContext"].pop("runAsNonRoot")):
        s = copy.deepcopy(base)
        mutate(s)
        assert pe.pss_level(s) == "baseline"


def test_extra_capability_breaks_baseline_but_net_bind_is_fine():
    s = spec("web-restricted")
    s["containers"][0]["securityContext"]["capabilities"]["add"] = ["NET_BIND_SERVICE"]
    assert pe.pss_level(s) == "restricted"
    s["containers"][0]["securityContext"]["capabilities"]["add"] = ["SYS_ADMIN"]
    assert pe.pss_level(s) == "privileged"


def test_host_namespaces_and_host_port_break_baseline():
    for patch in ({"hostNetwork": True}, {"hostPID": True}, {"hostIPC": True}):
        s = spec("web-restricted")
        s.update(patch)
        assert pe.pss_level(s) == "privileged"
    s = spec("web-restricted")
    s["containers"][0]["ports"] = [{"containerPort": 80, "hostPort": 80}]
    assert pe.pss_level(s) == "privileged"


def test_runtime_socket_mount_is_an_escape_path():
    s = spec("web-restricted")
    s["volumes"] = [{"name": "sock", "hostPath": {"path": "/var/run/containerd/containerd.sock"}}]
    assert "hostPath" in {e.kind for e in pe.escape_paths(s)}


def test_cronjob_pod_spec_is_found():
    cj = {"kind": "CronJob", "spec": {"jobTemplate": {"spec": {"template": {"spec": {"hostNetwork": True, "containers": []}}}}}}
    assert pe.pod_spec(cj)["hostNetwork"] is True


def test_module_06_linter_agrees_on_the_dangerous_settings():
    ids = pe.lint06(PATH)
    assert {"K8S-001", "K8S-006"} <= ids
