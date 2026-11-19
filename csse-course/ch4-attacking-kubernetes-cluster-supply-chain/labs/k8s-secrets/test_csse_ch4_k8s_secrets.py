import base64
from pathlib import Path

import yaml
from aisec_lab import load_lab_module

sc = load_lab_module(__file__, "secrets_check")
FIX = Path(__file__).parent / "fixtures"
SECRET = yaml.safe_load((FIX / "secret.yaml").read_text())
PODS = list(yaml.safe_load_all((FIX / "pods.yaml").read_text()))


def ids(text):
    return {i for i, _, _ in sc.audit_encryption_config(text)}


def test_base64_is_trivially_reversible():
    dec = sc.decode_secret(SECRET)
    assert dec == {"username": "shop_app", "password": "FAKE-not-a-real-password"}
    assert base64.b64encode(dec["username"].encode()).decode() == SECRET["data"]["username"]


def test_string_data_is_returned_as_is():
    assert sc.decode_secret({"stringData": {"k": "v"}}) == {"k": "v"}


def test_secret_in_git_is_flagged():
    assert sc.secrets_in_git([SECRET]) == ["Secret/shop/db-credentials"]
    assert sc.secrets_in_git([{"kind": "ConfigMap", "metadata": {"name": "x"}}]) == []


def test_identity_first_is_critical():
    assert "ENC-002" in ids((FIX / "encryption-config-bad.yaml").read_text())


def test_kms_v2_first_is_clean():
    assert sc.audit_encryption_config((FIX / "encryption-config-good.yaml").read_text()) == []


def test_missing_secrets_resource_is_critical():
    cfg = "apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n  - resources: [configmaps]\n    providers:\n      - identity: {}\n"
    assert ids(cfg) == {"ENC-001"}


def test_static_key_provider_is_medium():
    cfg = "apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n  - resources: [secrets]\n    providers:\n      - secretbox:\n          keys:\n            - {name: k1, secret: Zm9v}\n      - identity: {}\n"
    assert "ENC-004" in ids(cfg)


def test_kms_v1_flagged():
    cfg = "apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n  - resources: [secrets]\n    providers:\n      - kms: {name: x, endpoint: 'unix:///s'}\n"
    assert "ENC-006" in ids(cfg)


def test_env_versus_volume_consumption():
    env, vol = PODS
    assert len(sc.secret_consumption(env)["env"]) == 2 and sc.secret_consumption(env)["volumes"] == []
    assert sc.secret_consumption(vol) == {"env": [], "volumes": ["creds <- db-credentials"]}


def test_advice_prefers_volumes():
    env, vol = PODS
    assert any("environment variables" in a for a in sc.consumption_advice(env))
    assert any("envFrom" in a for a in sc.consumption_advice(env))
    assert sc.consumption_advice(vol) == []
