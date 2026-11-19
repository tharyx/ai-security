import pytest
from aisec_lab import load_lab_module

cd = load_lab_module(__file__, "cd")
DEPS = {"gateway": ["orders", "payments"], "orders": [], "payments": []}
KEY = cd.fake_signing_key()
V1 = {s: cd.build_image(f"registry.example/{s}", f"{s} v1") for s in DEPS}
V2 = {s: cd.build_image(f"registry.example/{s}", f"{s} v2") for s in DEPS}


def rel(svc, img=None, **kw):
    img = img or V2[svc]
    return cd.Release(svc, img, kw.get("signature", cd.sign(KEY, img)), kw.get("gates", True))


def deployer(broken=(), error=None):
    return cd.Deployer(KEY, DEPS, health=lambda s, i: i not in broken,
                       error_rate=error or (lambda s, i: 0.0))


def cluster(n=3):
    return cd.Cluster("c", {s: [V1[s]] * n for s in DEPS})


def test_backends_deploy_before_the_gateway():
    order = deployer().order(list(DEPS))
    assert order.index("gateway") > order.index("orders") and order.index("gateway") > order.index("payments")


def test_dependency_cycle_is_detected():
    d = cd.Deployer(KEY, {"a": ["b"], "b": ["a"]}, health=lambda s, i: True)
    with pytest.raises(ValueError):
        d.order(["a", "b"])


def test_mutable_tag_unsigned_and_ungated_images_are_rejected():
    d = deployer()
    c = cluster()
    res = d.deploy(c, [rel("orders", "registry.example/orders:latest"),
                       rel("payments", signature="00" * 32),
                       cd.Release("gateway", V2["gateway"], cd.sign(KEY, V2["gateway"]), False)], env="staging")
    assert "pinned by digest" in res["orders"] and "signature" in res["payments"]
    assert res["gateway"].startswith("rejected") and "security gates" in res["gateway"]
    assert c.replicas["orders"] == [V1["orders"]] * 3


def test_signature_from_another_key_does_not_verify():
    other = cd.sign(cd.fake_signing_key(), V2["orders"])
    assert "signature" in deployer().deploy(cluster(), [rel("orders", signature=other)], env="staging")["orders"]


def test_prod_requires_the_same_digest_to_pass_staging_first():
    d = deployer()
    assert "never succeeded in staging" in d.deploy(cluster(), [rel("orders")], env="prod")["orders"]
    d.deploy(cluster(), [rel("orders")], env="staging")
    assert d.deploy(cluster(), [rel("orders")], env="prod")["orders"] == "deployed"


def test_rolling_update_replaces_all_replicas_when_healthy():
    c = cluster(4)
    assert deployer().deploy(c, [rel("orders")], env="staging")["orders"] == "deployed"
    assert c.replicas["orders"] == [V2["orders"]] * 4


def test_failed_health_check_rolls_back_and_skips_dependents():
    c = cluster()
    res = deployer(broken={V2["payments"]}).deploy(c, [rel(s) for s in DEPS], env="staging")
    assert res["payments"] == "rolled-back" and c.replicas["payments"] == [V1["payments"]] * 3
    assert res["gateway"].startswith("skipped") and c.replicas["gateway"] == [V1["gateway"]] * 3
    assert res["orders"] == "deployed"


def test_canary_with_high_error_rate_is_rolled_back_and_low_is_promoted():
    bad = deployer(error=lambda s, i: 0.08 if i == V2["orders"] else 0.005)
    c = cluster()
    assert bad.deploy(c, [rel("orders")], env="staging", strategy="canary")["orders"] == "rolled-back"
    assert c.replicas["orders"] == [V1["orders"]] * 3
    good = deployer(error=lambda s, i: 0.004)
    assert good.deploy(c, [rel("orders")], env="staging", strategy="canary")["orders"] == "deployed"
    assert any("canary promoted" in a for a in good.audit)
