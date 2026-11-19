from pathlib import Path

import pytest
import yaml
from aisec_lab import load_lab_module

hr = load_lab_module(__file__, "helm_render")
sc = load_lab_module(__file__, "static_check")
wa = load_lab_module(__file__, "webhook_audit")
FIX = Path(__file__).parent / "fixtures"
CHART = FIX / "chart"
SECURE_VALUES = yaml.safe_load((CHART / "values-secure.yaml").read_text())


def ids(findings):
    return {f.rule_id for f in findings}


# ---- template engine
def test_substitution_quote_default_upper():
    ctx = {"Values": {"a": {"b": "x"}, "n": 0}}
    assert hr.render("{{ .Values.a.b }}", ctx) == "x"
    assert hr.render("{{ .Values.a.b | quote }}", ctx) == '"x"'
    assert hr.render("{{ .Values.n | default 3 }}", ctx) == "3"
    assert hr.render("{{ .Values.missing | default \"z\" }}", ctx) == "z"
    assert hr.render("{{ .Values.a.b | upper }}", ctx) == "X"


def test_if_else_end_and_trimming():
    t = "a\n{{- if .Values.on }}\nB\n{{- else }}\nC\n{{- end }}\nd"
    assert hr.render(t, {"Values": {"on": True}}) == "a\nB\nd"
    assert hr.render(t, {"Values": {"on": False}}) == "a\nC\nd"


def test_unsupported_features_fail_loudly():
    with pytest.raises(hr.TemplateError):
        hr.render("{{ include \"x\" . }}", {"Values": {}})
    with pytest.raises(hr.TemplateError):
        hr.render("{{ if .Values.a }}open", {"Values": {"a": True}})


def test_deep_merge_overrides_nested_values():
    assert hr.deep_merge({"a": {"b": 1, "c": 2}}, {"a": {"b": 9}}) == {"a": {"b": 9, "c": 2}}


# ---- chart render and checks
def test_default_values_render_dangerous_objects():
    docs = hr.render_chart(CHART)
    kinds = {d["kind"] for d in docs}
    assert {"Deployment", "Service", "ClusterRoleBinding", "Job"} <= kinds
    dep = next(d for d in docs if d["kind"] == "Deployment")
    assert dep["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:latest"
    assert dep["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] is True


def test_secure_values_remove_binding_and_hook():
    docs = hr.render_chart(CHART, SECURE_VALUES)
    assert {d["kind"] for d in docs} == {"Deployment", "Service"}
    image = next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]["image"]
    assert image.startswith("registry.corp.example/shop/web@sha256:")


def test_default_chart_has_helm_supply_chain_findings():
    got = ids(sc.analyse_chart(CHART))
    assert {"HELM-001", "HELM-002", "HELM-003", "HELM-004", "HELM-005", "HELM-006", "HELM-007", "HELM-008"} <= got
    assert {"K8S-001", "K8S-006"} <= got  # privileged + host network from the module-06 rules


def test_secure_values_clear_workload_and_hook_findings_but_not_chart_level_ones():
    got = ids(sc.analyse_chart(CHART, SECURE_VALUES))
    assert not ({"HELM-007", "HELM-008", "K8S-001", "K8S-006"} & got)
    assert {"HELM-001", "HELM-003", "HELM-004"} <= got  # unsigned, unlocked, http repo remain


def test_provenance_file_clears_helm_004():
    import shutil
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        dst = Path(tmp) / "chart"
        shutil.copytree(CHART, dst)
        (dst / "shop-web-0.3.0.tgz.prov").write_text("FAKE PROVENANCE FILE")
        (dst / "Chart.lock").write_text("dependencies: []\n")
        got = ids(sc.chart_checks(dst, hr.render_chart(dst)))
    assert "HELM-004" not in got and "HELM-003" not in got


def test_module_06_checker_on_plain_manifests():
    got = ids(sc.check_manifests(FIX / "manifests/bad-deployment.yaml"))
    assert {"K8S-001", "K8S-006", "K8S-007", "K8S-009"} <= got


# ---- webhooks
def test_webhook_audit_findings():
    docs = wa.load((FIX / "webhooks.yaml").read_text())
    by = {}
    for f in wa.audit(docs):
        by.setdefault(f.where.split(":")[0], set()).add(f.rule_id)
    assert {"WH-001", "WH-002", "WH-003", "WH-005", "WH-006"} <= by["ValidatingWebhookConfiguration/policy-enforcer"]
    assert {"WH-007", "WH-008"} <= by["MutatingWebhookConfiguration/sidecar-injector"]
    assert "ValidatingWebhookConfiguration/good-policy" not in by


def test_bypass_simulation():
    weak = wa.load((FIX / "webhooks.yaml").read_text())[0]["webhooks"][0]
    assert wa.admits(weak, {"policy-exempt": "x"}, webhook_down=False).startswith("ADMIT")
    assert wa.admits(weak, {}, webhook_down=True).startswith("ADMIT")
    assert wa.admits({**weak, "failurePolicy": "Fail"}, {}, webhook_down=True).startswith("REJECT")
    assert wa.admits(weak, {}, webhook_down=False).startswith("CALL")


def test_good_webhook_excludes_only_system_namespaces():
    good = wa.load((FIX / "webhooks.yaml").read_text())[2]["webhooks"][0]
    assert wa.admits(good, {"kubernetes.io/metadata.name": "kube-system"}, webhook_down=False).startswith("ADMIT")
    assert wa.admits(good, {"kubernetes.io/metadata.name": "shop"}, webhook_down=True).startswith("REJECT")
