"""Tests for the Helm chart scanner."""

import copy
import hashlib

from aisec_lab import load_lab_module

h = load_lab_module(__file__, "helm_scan")


def ids(**kw):
    return {c for c, _, _ in h.check_chart(h.CHART, **kw)}


def test_render_substitutes_values_and_default():
    values, docs = h.render_chart(h.CHART)
    c = docs[0]["spec"]["template"]["spec"]["containers"][0]
    assert c["image"] == "shop/api:latest" and c["securityContext"]["privileged"] is False


def test_render_default_filter_used_for_empty_value():
    assert h.render('{{ .Values.x | default "fallback" }}', {"x": ""}) == "fallback"


def test_overrides_change_render():
    _, docs = h.render_chart(h.CHART, h.HARDENED_OVERRIDES)
    c = docs[0]["spec"]["template"]["spec"]["containers"][0]
    assert "@sha256:" in c["image"] and c["securityContext"]["runAsNonRoot"] is True


def test_default_values_fail_key_checks():
    assert {"HELM-01", "HELM-02", "HELM-03", "HELM-04", "HELM-06", "HELM-07", "HELM-08"} <= ids()


def test_hardened_overrides_fix_rendered_problems_but_not_chart_metadata():
    r = ids(overrides=h.HARDENED_OVERRIDES)
    assert not ({"HELM-04", "HELM-06", "HELM-07"} & r)
    assert {"HELM-01", "HELM-02"} <= r  # http repo and missing lock are chart issues, not values


def test_privileged_override_is_critical():
    f = h.check_chart(h.CHART, {"securityContext": {"privileged": True}})
    assert ("HELM-05", "critical") in {(c, s) for c, s, _ in f}


def test_provenance_match_and_mismatch():
    good = hashlib.sha256(h.CHART["Chart.yaml"].encode()).hexdigest()
    assert "HELM-03" not in ids(prov_digest=good)
    f = h.check_chart(h.CHART, prov_digest="0" * 64)
    assert ("HELM-03", "critical") in {(c, s) for c, s, _ in f}


def test_chart_lock_and_https_repo_clear_findings():
    chart = copy.deepcopy(h.CHART)
    chart["Chart.lock"] = "digest: sha256:abc"
    chart["Chart.yaml"] = chart["Chart.yaml"].replace("http://", "https://")
    r = {c for c, _, _ in h.check_chart(chart)}
    assert "HELM-01" not in r and "HELM-02" not in r


def test_deep_merge_keeps_unrelated_keys():
    m = h.deep_merge({"a": {"b": 1, "c": 2}}, {"a": {"b": 9}})
    assert m == {"a": {"b": 9, "c": 2}}
