from pathlib import Path

import yaml
from aisec_lab import load_lab_module

sa = load_lab_module(__file__, "sa_check")
DOCS = list(yaml.safe_load_all((Path(__file__).parent / "fixtures/sa-and-pods.yaml").read_text()))
NOW = 1_000_100


def where_rule(rule):
    return {f.where for f in sa.analyse(DOCS) if f.rule_id == rule}


def test_default_sa_with_automount_is_flagged():
    assert "Pod/shop/sloppy" in where_rule("SA-001") and "Pod/shop/sloppy" in where_rule("SA-002")


def test_sa_level_automount_false_is_honoured():
    assert "Pod/shop/web-1" not in where_rule("SA-001")


def test_pod_level_setting_overrides_and_annotation_justifies():
    assert "Pod/shop/operator-1" not in where_rule("SA-001")


def test_legacy_secret_token_reference_is_flagged():
    assert where_rule("SA-005") == {"ServiceAccount/shop/legacy-sa"}


def test_projected_token_audience_and_lifetime():
    assert where_rule("SA-003") == {"Pod/shop/long-lived"}
    assert where_rule("SA-004") == {"Pod/shop/long-lived"}


def test_claims_are_readable_without_a_key():
    token = sa.make_token(sa.bound_claims("shop", "web", "web-1", "uid-1"))
    assert sa.decode_claims(token)["sub"] == "system:serviceaccount:shop:web"


def test_valid_bound_token_is_accepted():
    token = sa.make_token(sa.bound_claims("shop", "web", "web-1", "uid-1"))
    assert sa.token_review(token, audience=sa.DEFAULT_AUDIENCE, now=NOW, live_pod_uids={"uid-1"})[0]


def test_audience_mismatch_blocks_replay_to_another_service():
    token = sa.make_token(sa.bound_claims("shop", "web", "web-1", "uid-1", audience="https://vault.example"))
    ok, why = sa.token_review(token, audience="https://other.example", now=NOW, live_pod_uids={"uid-1"})
    assert not ok and "audience" in why


def test_token_dies_with_its_pod_and_with_time():
    token = sa.make_token(sa.bound_claims("shop", "web", "web-1", "uid-1"))
    assert "no longer exists" in sa.token_review(token, audience=sa.DEFAULT_AUDIENCE, now=NOW, live_pod_uids=set())[1]
    assert "expired" in sa.token_review(token, audience=sa.DEFAULT_AUDIENCE, now=NOW + 10_000, live_pod_uids={"uid-1"})[1]


def test_legacy_token_has_no_expiry_and_is_flagged():
    ok, why = sa.token_review(sa.make_token(sa.legacy_claims("shop", "legacy-sa")), audience=sa.DEFAULT_AUDIENCE, now=10**12, live_pod_uids=set())
    assert ok and "legacy" in why
