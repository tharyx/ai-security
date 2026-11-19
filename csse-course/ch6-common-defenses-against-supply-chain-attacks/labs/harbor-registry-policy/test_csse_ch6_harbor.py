"""Tests for the Harbor-style registry policy simulator."""

from datetime import date

import pytest

from aisec_lab import load_lab_module

r = load_lab_module(__file__, "registry")
TODAY = date(2026, 11, 19)


@pytest.fixture
def reg():
    g = r.Registry(TODAY)
    g.create_project(r.Project("prod", immutable_patterns=("v",), prevent_vulnerable=True, severity_threshold="HIGH"))
    g.create_project(r.Project("open", public=True))
    g.create_robot(r.Robot("ci", "prod", {"push"}, date(2027, 1, 1)))
    g.create_robot(r.Robot("puller", "prod", {"pull"}, date(2027, 1, 1)))
    g.create_robot(r.Robot("old", "prod", {"pull", "push"}, date(2026, 1, 1)))
    return g


def test_push_then_authorized_pull(reg):
    reg.push("ci", r.Artifact("prod/api", "v1", "sha256:a", []))
    assert reg.pull("puller", "prod/api", "v1").digest == "sha256:a"


def test_robot_scoped_to_permission(reg):
    with pytest.raises(r.PolicyError, match="lacks 'push'"):
        reg.push("puller", r.Artifact("prod/api", "v1", "sha256:a", []))


def test_robot_scoped_to_project(reg):
    reg.create_robot(r.Robot("other", "open", {"push"}, date(2027, 1, 1)))
    with pytest.raises(r.PolicyError):
        reg.push("other", r.Artifact("prod/api", "v1", "sha256:a", []))


def test_expired_robot_rejected(reg):
    with pytest.raises(r.PolicyError, match="expired"):
        reg.push("old", r.Artifact("prod/api", "v1", "sha256:a", []))


def test_immutable_tag_cannot_be_overwritten_but_mutable_can(reg):
    reg.push("ci", r.Artifact("prod/api", "v1", "sha256:a", []))
    with pytest.raises(r.PolicyError, match="immutable"):
        reg.push("ci", r.Artifact("prod/api", "v1", "sha256:b", []))
    reg.push("ci", r.Artifact("prod/api", "latest", "sha256:a", []))
    reg.push("ci", r.Artifact("prod/api", "latest", "sha256:b", []))
    assert reg.artifacts[("prod/api", "latest")].digest == "sha256:b"


def test_private_project_denies_anonymous_public_allows(reg):
    reg.push("ci", r.Artifact("prod/api", "v1", "sha256:a", []))
    with pytest.raises(r.PolicyError, match="private"):
        reg.pull(None, "prod/api", "v1")
    reg.artifacts[("open/web", "1")] = r.Artifact("open/web", "1", "sha256:z", [])
    assert reg.pull(None, "open/web", "1")


def test_prevent_vulnerable_blocks_high_and_above_only(reg):
    reg.push("ci", r.Artifact("prod/a", "t1", "sha256:1", [("EX-1", "MEDIUM")]))
    reg.push("ci", r.Artifact("prod/a", "t2", "sha256:2", [("EX-2", "CRITICAL")]))
    assert reg.pull("puller", "prod/a", "t1")
    with pytest.raises(r.PolicyError, match="EX-2"):
        reg.pull("puller", "prod/a", "t2")


def test_cve_allowlist_is_time_boxed(reg):
    reg.push("ci", r.Artifact("prod/a", "t2", "sha256:2", [("EX-2", "CRITICAL")]))
    reg.projects["prod"].cve_allowlist["EX-2"] = date(2026, 12, 1)
    assert reg.pull("puller", "prod/a", "t2")
    reg.today = date(2026, 12, 2)
    with pytest.raises(r.PolicyError):
        reg.pull("puller", "prod/a", "t2")


def test_signature_required(reg):
    reg.projects["prod"].require_signature = True
    reg.push("ci", r.Artifact("prod/s", "t", "sha256:s", [], signed=False))
    with pytest.raises(r.PolicyError, match="not signed"):
        reg.pull("puller", "prod/s", "t")
    reg.push("ci", r.Artifact("prod/s", "t2", "sha256:s2", [], signed=True))
    assert reg.pull("puller", "prod/s", "t2")


def test_missing_artifact(reg):
    with pytest.raises(r.PolicyError, match="not found"):
        reg.pull("puller", "prod/none", "x")
