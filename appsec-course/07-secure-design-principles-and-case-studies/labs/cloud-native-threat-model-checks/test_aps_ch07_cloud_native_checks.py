import copy
from pathlib import Path

from aisec_lab import load_lab_module

cn = load_lab_module(__file__, "cn_checks")
FIX = Path(__file__).resolve().parent / "fixtures"
S3_BAD, S3_GOOD = cn.load_json(FIX / "s3_insecure.json"), cn.load_json(FIX / "s3_hardened.json")
K8S_BAD, K8S_GOOD = cn.load_json(FIX / "k8s_insecure.json"), cn.load_json(FIX / "k8s_hardened.json")
FTP_BAD = (FIX / "vsftpd_insecure.conf").read_text(encoding="utf-8")
FTP_GOOD = (FIX / "vsftpd_hardened.conf").read_text(encoding="utf-8")


def failed_ids(findings):
    return {f.threat for f in cn.failed(findings)}


def test_insecure_bucket_fails_every_s3_mitigation():
    assert failed_ids(cn.check_s3(S3_BAD)) == {f"S3-T{i}" for i in range(1, 10)}


def test_hardened_bucket_passes():
    assert cn.failed(cn.check_s3(S3_GOOD)) == [] and cn.gate(cn.check_s3(S3_GOOD)) == 0


def test_public_principal_with_condition_is_not_flagged_but_unconditional_is():
    b = copy.deepcopy(S3_GOOD)
    b["policy"]["Statement"].append({"Sid": "Oops", "Effect": "Allow", "Principal": {"AWS": "*"},
                                     "Action": "s3:GetObject", "Resource": "x"})
    assert "S3-T2" in failed_ids(cn.check_s3(b))
    b["policy"]["Statement"][-1]["Condition"] = {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}
    assert "S3-T2" not in failed_ids(cn.check_s3(b))


def test_insecure_kubernetes_manifests_fail_container_escape_and_rbac_checks():
    ids = failed_ids(cn.check_k8s(K8S_BAD))
    assert {"K8S-T1", "K8S-T2", "K8S-T4", "K8S-T6", "K8S-T8", "K8S-T9", "K8S-T10", "K8S-T11", "K8S-T12"} <= ids


def test_hardened_kubernetes_manifests_pass():
    assert cn.failed(cn.check_k8s(K8S_GOOD)) == []


def test_latest_tag_and_literal_secret_are_caught_individually():
    objs = copy.deepcopy(K8S_GOOD)
    c = objs[2]["spec"]["template"]["spec"]["containers"][0]
    c["image"] = "registry.example/shop/orders-api:latest"
    c["env"] = [{"name": "API_TOKEN", "value": "FAKE"}]
    assert failed_ids(cn.check_k8s(objs)) == {"K8S-T6", "K8S-T8"}


def test_vsftpd_insecure_vs_hardened():
    assert failed_ids(cn.check_vsftpd(FTP_BAD)) == {f"FTP-T{i}" for i in range(1, 8)}
    assert cn.failed(cn.check_vsftpd(FTP_GOOD)) == []


def test_missing_anonymous_setting_is_treated_as_unsafe():
    text = FTP_GOOD.replace("anonymous_enable=NO\n", "")
    assert "FTP-T1" in failed_ids(cn.check_vsftpd(text))
