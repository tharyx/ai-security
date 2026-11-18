"""Synthetic CloudTrail-style events and IAM policies for the lab.

Everything is fake: account 111122223333, documentation-range IPs, *.example names.
Run `python sample_data.py` to (re)write sample_cloudtrail.json next to this file.
"""

from __future__ import annotations

import json
from pathlib import Path

ACCOUNT = "111122223333"
DAY = "2026-03-10"


def _ev(time, name, user=None, ip="192.0.2.10", source="iam.amazonaws.com", key=None,
        request=None, response=None, extra=None, utype="IAMUser", error=None):
    ident = {"type": utype, "accountId": ACCOUNT}
    if utype == "Root":
        ident["arn"] = f"arn:aws:iam::{ACCOUNT}:root"
    else:
        ident["userName"] = user
        ident["arn"] = f"arn:aws:iam::{ACCOUNT}:user/{user}"
    if key:
        ident["accessKeyId"] = key
    ev = {
        "eventVersion": "1.09", "eventTime": f"{DAY}T{time}Z", "eventSource": source,
        "eventName": name, "awsRegion": "ca-central-1", "sourceIPAddress": ip,
        "userIdentity": ident, "requestParameters": request, "responseElements": response,
    }
    if extra:
        ev["additionalEventData"] = extra
    if error:
        ev["errorCode"] = error
    return ev


def _login(time, user, ip, ok=True, mfa=True, utype="IAMUser"):
    return _ev(time, "ConsoleLogin", user, ip, "signin.amazonaws.com", utype=utype,
               response={"ConsoleLogin": "Success" if ok else "Failure"},
               extra={"MFAUsed": "Yes" if mfa else "No"})


def benign_events() -> list[dict]:
    """Normal admin day: logins with MFA, key rotation, a private bucket policy."""
    ok_policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/Auditor"},
        "Action": "s3:GetObject", "Resource": "arn:aws:s3:::corp-logs/*"}]}
    return [
        _ev("08:00:00", "ListBuckets", "svc-report", "198.51.100.7", "s3.amazonaws.com", key="AKIAEXAMPLESVC0"),
        _ev("08:30:00", "GetObject", "carol", "192.0.2.20", "s3.amazonaws.com", key="AKIAEXAMPLECAROL0"),
        _login("08:55:00", "alice", "192.0.2.10"),
        _ev("09:00:00", "DescribeInstances", "alice", "192.0.2.10", "ec2.amazonaws.com", key="AKIAEXAMPLEALICE0"),
        _ev("09:05:00", "CreateAccessKey", "alice", "192.0.2.10", key="AKIAEXAMPLEALICE0",
            request={"userName": "svc-report"},
            response={"accessKey": {"accessKeyId": "AKIAEXAMPLESVC1", "userName": "svc-report"}}),
        _ev("09:10:00", "PutBucketPolicy", "alice", "192.0.2.10", "s3.amazonaws.com", key="AKIAEXAMPLEALICE0",
            request={"bucketName": "corp-logs", "bucketPolicy": ok_policy}),
        _login("09:20:00", "bob", "192.0.2.30", ok=False),
        _login("09:20:40", "bob", "192.0.2.30", ok=False),
        _login("09:21:30", "bob", "192.0.2.30", ok=True),
        _ev("09:30:00", "ListBuckets", "svc-report", "198.51.100.7", "s3.amazonaws.com", key="AKIAEXAMPLESVC1"),
        _ev("09:40:00", "DeleteAccessKey", "alice", "192.0.2.10", key="AKIAEXAMPLEALICE0",
            request={"userName": "svc-report", "accessKeyId": "AKIAEXAMPLESVC0"}),
    ]


def attack_events() -> list[dict]:
    public_policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::corp-customer-exports/*"}]}
    ev = [
        _login("02:10:00", None, "203.0.113.50", mfa=False, utype="Root"),
        # password guessing against erin, then success
        *[_login(f"03:0{i}:{10 * i:02d}", "erin", "203.0.113.99", ok=False, mfa=False) for i in range(6)],
        _login("03:07:00", "erin", "203.0.113.99", ok=True, mfa=False),
        # key created from the normal country, used from a new one
        _ev("11:30:00", "CreateAccessKey", "carol", "192.0.2.20", key="AKIAEXAMPLECAROL0",
            request={"userName": "carol"},
            response={"accessKey": {"accessKeyId": "AKIAEXAMPLENEW01", "userName": "carol"}}),
        _ev("11:40:00", "GetCallerIdentity", "carol", "203.0.113.77", "sts.amazonaws.com", key="AKIAEXAMPLENEW01"),
        _ev("11:45:00", "StopLogging", "carol", "203.0.113.77", "cloudtrail.amazonaws.com", key="AKIAEXAMPLENEW01",
            request={"name": "org-trail"}),
        _ev("11:50:00", "PutBucketPolicy", "carol", "203.0.113.77", "s3.amazonaws.com", key="AKIAEXAMPLENEW01",
            request={"bucketName": "corp-customer-exports", "bucketPolicy": public_policy}),
        _ev("11:55:00", "DeleteTrail", "carol", "203.0.113.77", "cloudtrail.amazonaws.com", key="AKIAEXAMPLENEW01",
            request={"name": "org-trail"}),
    ]
    return ev


def all_events() -> list[dict]:
    return benign_events() + attack_events()


SAMPLE_POLICIES = {
    "AdministratorAccess-like": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    "DevOpsPassRole": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances", "lambda:CreateFunction"],
         "Resource": "*"}]},
    "S3AppLeastPrivilege": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
         "Resource": "arn:aws:s3:::app-data-bucket/reports/*"}]},
    "IamManagerNoMfa": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["iam:CreateUser", "iam:AttachUserPolicy"],
         "Resource": "arn:aws:iam::111122223333:user/*"}]},
    "IamManagerWithMfa": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["iam:CreateUser", "iam:AttachUserPolicy"],
         "Resource": "arn:aws:iam::111122223333:user/*",
         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]},
    "ReadOnlyAuditor": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["ec2:Describe*", "s3:List*", "s3:GetBucketPolicy", "cloudtrail:LookupEvents"],
         "Resource": "*"}]},
    "AdminWithMfaGuard": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["ec2:*"], "Resource": "arn:aws:ec2:ca-central-1:111122223333:*"},
        {"Effect": "Deny", "Action": "*", "Resource": "*",
         "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}}]},
    "NotActionTrap": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]},
}


if __name__ == "__main__":
    out = Path(__file__).with_name("sample_cloudtrail.json")
    out.write_text(json.dumps({"Records": all_events()}, indent=2), encoding="utf-8")
    print(f"wrote {out.name}: {len(all_events())} events")
