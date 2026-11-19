"""Tests for the storage / CDN / DNS auditor (fixtures only)."""

import copy
from pathlib import Path

from aisec_lab import load_lab_module

a = load_lab_module(__file__, "audit")
ESTATE = a.load(Path(__file__).resolve().parent / "fixtures" / "estate.json")


def rules(findings, resource=None):
    return {f.rule for f in findings if resource is None or f.resource == resource}


def test_s3_public_read_and_write_detected():
    f = a.audit_s3(ESTATE["s3"])
    assert "S3-PUBLIC-READ" in rules(f, "acme-public-assets")
    assert "S3-PUBLIC-WRITE" in rules(f, "acme-uploads")
    assert any(x.severity == "critical" for x in f if x.rule == "S3-PUBLIC-WRITE")


def test_s3_acl_and_website_detected():
    f = a.audit_s3(ESTATE["s3"])
    assert {"S3-ACL-ALLUSERS", "S3-WEBSITE-HTTP"} <= rules(f, "acme-marketing-site")


def test_locked_down_bucket_is_clean_and_condition_policy_ignored():
    assert a.audit_s3([b for b in ESTATE["s3"] if b["name"] == "acme-build-artifacts"]) == []


def test_block_public_access_neutralises_public_policy():
    b = copy.deepcopy(ESTATE["s3"][0])
    b["block_public_access"] = True
    assert "S3-PUBLIC-READ" not in rules(a.audit_s3([b]))


def test_azure_public_container_sas_and_https():
    f = a.audit_azure(ESTATE["azure_blob"])
    assert {"AZ-BLOB-PUBLIC", "AZ-HTTP-ALLOWED", "AZ-SHARED-KEY", "AZ-SAS-LONG-LIVED"} <= rules(f)
    assert not [x for x in f if x.resource.startswith("acmestorage2")]


def test_azure_account_level_switch_overrides_container_setting():
    acct = copy.deepcopy(ESTATE["azure_blob"][0])
    acct["allow_blob_public_access"] = False
    assert "AZ-BLOB-PUBLIC" not in rules(a.audit_azure([acct]))


def test_gcs_public_read_vs_write():
    f = a.audit_gcs(ESTATE["gcs"])
    assert "GCS-PUBLIC-READ" in rules(f, "acme-ml-exports")
    assert "GCS-PUBLIC-WRITE" in rules(f, "acme-shared-writes")
    assert not rules(f, "acme-logs")


def test_cdn_origin_without_oac_and_website_origin():
    f = a.audit_cdn(ESTATE["cdn"], ESTATE["s3"], ESTATE["existing_buckets"])
    assert any(x.rule == "CDN-NO-OAC" and x.severity == "high" and x.resource == "d111-assets" for x in f)
    assert "CDN-WEBSITE-ORIGIN" in rules(f, "d222-site")
    assert not rules(f, "d333-builds")


def test_cdn_origin_missing_is_critical_takeover():
    f = a.audit_cdn(ESTATE["cdn"], ESTATE["s3"], ESTATE["existing_buckets"])
    assert any(x.rule == "CDN-ORIGIN-MISSING" and x.severity == "critical" for x in f)


def test_dangling_dns_detected_and_live_records_ok():
    f = a.audit_dns(ESTATE["dns"], ESTATE["existing_targets"])
    assert {x.resource for x in f} == {"docs.acme.example", "files.acme.example"}


def test_full_audit_sorted_most_severe_first():
    f = a.audit(ESTATE)
    order = [a.SEV_ORDER[x.severity] for x in f]
    assert order == sorted(order) and f[0].severity == "critical"
