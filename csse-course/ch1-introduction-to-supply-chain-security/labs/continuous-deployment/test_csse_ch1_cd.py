"""Tests for the continuous-deployment model."""

import pytest

from aisec_lab import load_lab_module

cd = load_lab_module(__file__, "cd")


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


@pytest.fixture
def sys_():
    clock = Clock()
    s = cd.DeploymentSystem(clock=clock, approval_ttl=100)
    s.register_artifact("1.0", "build-one")
    s.register_artifact("1.1", "build-two")
    s.clock_obj = clock
    return s


def promote_to_staging(s, v):
    assert s.deploy("dev", v, "ci") == "deployed"
    assert s.deploy("staging", v, "ci") == "deployed"


def go_prod(s, v, requester="dev-alice", approver="release-manager"):
    s.request_approval("prod", v, requester)
    s.approve("prod", v, approver)
    return s.deploy("prod", v, requester)


def test_digest_is_stable_and_differs():
    assert cd.digest_of("a") == cd.digest_of("a") != cd.digest_of("b")


def test_must_follow_environment_order(sys_):
    with pytest.raises(cd.DeployError, match="dev first|staging first"):
        sys_.deploy("staging", "1.0", "ci")
    sys_.deploy("dev", "1.0", "ci")
    with pytest.raises(cd.DeployError, match="staging first"):
        sys_.deploy("prod", "1.0", "ci")


def test_unknown_version_rejected(sys_):
    with pytest.raises(cd.DeployError, match="never built"):
        sys_.deploy("dev", "9.9", "ci")


def test_digest_mismatch_rejected(sys_):
    with pytest.raises(cd.DeployError, match="digest mismatch"):
        sys_.deploy("dev", "1.0", "ci", digest="sha256:evil")


def test_same_digest_everywhere(sys_):
    promote_to_staging(sys_, "1.0")
    go_prod(sys_, "1.0")
    digests = {e.current.digest for e in sys_.envs.values()}
    assert digests == {sys_.artifacts["1.0"]}


def test_prod_requires_approval(sys_):
    promote_to_staging(sys_, "1.0")
    with pytest.raises(cd.DeployError, match="approval required"):
        sys_.deploy("prod", "1.0", "dev-alice")


def test_self_approval_is_refused(sys_):
    promote_to_staging(sys_, "1.0")
    sys_.request_approval("prod", "1.0", "release-manager")
    with pytest.raises(cd.DeployError, match="separation of duties"):
        sys_.approve("prod", "1.0", "release-manager")


def test_non_approver_cannot_approve(sys_):
    promote_to_staging(sys_, "1.0")
    sys_.request_approval("prod", "1.0", "dev-alice")
    with pytest.raises(cd.DeployError, match="not an approver"):
        sys_.approve("prod", "1.0", "dev-bob")


def test_only_requester_can_run_approved_deploy(sys_):
    promote_to_staging(sys_, "1.0")
    sys_.request_approval("prod", "1.0", "dev-alice")
    sys_.approve("prod", "1.0", "security-lead")
    with pytest.raises(cd.DeployError, match="requested"):
        sys_.deploy("prod", "1.0", "mallory")


def test_prod_only_from_protected_branch(sys_):
    promote_to_staging(sys_, "1.0")
    sys_.request_approval("prod", "1.0", "dev-alice")
    sys_.approve("prod", "1.0", "release-manager")
    with pytest.raises(cd.DeployError, match="not protected"):
        sys_.deploy("prod", "1.0", "dev-alice", branch="feature-x")


def test_approval_is_single_use(sys_):
    promote_to_staging(sys_, "1.0")
    go_prod(sys_, "1.0")
    with pytest.raises(cd.DeployError, match="approval required"):
        sys_.deploy("prod", "1.0", "dev-alice")


def test_approval_expires(sys_):
    promote_to_staging(sys_, "1.0")
    sys_.request_approval("prod", "1.0", "dev-alice")
    sys_.approve("prod", "1.0", "release-manager")
    sys_.clock_obj.t += 101
    with pytest.raises(cd.DeployError, match="expired"):
        sys_.deploy("prod", "1.0", "dev-alice")


def test_approval_for_a_swapped_digest_is_refused(sys_):
    promote_to_staging(sys_, "1.0")
    sys_.request_approval("prod", "1.0", "dev-alice")
    sys_.approve("prod", "1.0", "release-manager")
    sys_.artifacts["1.0"] = cd.digest_of("tampered")  # artifact changed after approval
    with pytest.raises(cd.DeployError):
        sys_.deploy("prod", "1.0", "dev-alice")


def test_failed_health_check_rolls_back_automatically(sys_):
    promote_to_staging(sys_, "1.0")
    go_prod(sys_, "1.0")
    promote_to_staging(sys_, "1.1")
    sys_.request_approval("prod", "1.1", "dev-alice")
    sys_.approve("prod", "1.1", "release-manager")
    result = sys_.deploy("prod", "1.1", "dev-alice", healthy=lambda r: False)
    assert result == "rolled_back"
    assert sys_.envs["prod"].current.version == "1.0"
    assert [a["event"] for a in sys_.audit if a["event"] == "auto_rollback"]


def test_first_deploy_failure_leaves_env_empty(sys_):
    assert sys_.deploy("dev", "1.0", "ci", healthy=lambda r: False) == "rolled_back"
    assert sys_.envs["dev"].current is None


def test_manual_rollback_restores_old_release_and_digest(sys_):
    promote_to_staging(sys_, "1.0")
    go_prod(sys_, "1.0")
    promote_to_staging(sys_, "1.1")
    go_prod(sys_, "1.1")
    assert sys_.state()["prod"] == "1.1"
    cur = sys_.rollback("prod", "1.0", "release-manager")
    assert cur.version == "1.0" and cur.digest == sys_.artifacts["1.0"]
    assert sys_.state()["prod"] == "1.0"


def test_rollback_in_prod_needs_an_approver_role(sys_):
    promote_to_staging(sys_, "1.0")
    go_prod(sys_, "1.0")
    with pytest.raises(cd.DeployError, match="may not roll back"):
        sys_.rollback("prod", "1.0", "dev-bob")


def test_cannot_roll_back_to_a_release_that_never_worked(sys_):
    promote_to_staging(sys_, "1.0")
    go_prod(sys_, "1.0")
    promote_to_staging(sys_, "1.1")
    sys_.request_approval("prod", "1.1", "dev-alice")
    sys_.approve("prod", "1.1", "release-manager")
    sys_.deploy("prod", "1.1", "dev-alice", healthy=lambda r: False)
    with pytest.raises(cd.DeployError, match="never successfully"):
        sys_.rollback("prod", "1.1", "release-manager")


def test_audit_trail_records_who_approved_what(sys_):
    promote_to_staging(sys_, "1.0")
    go_prod(sys_, "1.0")
    ev = [a for a in sys_.audit if a["event"] == "approved"][0]
    assert ev["approver"] == "release-manager" and ev["digest"] == sys_.artifacts["1.0"]
