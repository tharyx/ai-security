import pytest
from aisec_lab import load_lab_module

m = load_lab_module(__file__, "delegator_worker")
TASK = """Plan the week
- Summarize public release notes about the framework
- Draft a note for employee Alice about the internal only roadmap
- Check patient record FAKE-SSN-123 against the form
"""


def test_classification_levels():
    assert m.classify("hello world") == m.PUBLIC
    assert m.classify("internal only roadmap") == m.INTERNAL
    assert m.classify("token FAKE-KEY-abc123") == m.RESTRICTED
    assert m.classify("internal roadmap and CONFIDENTIAL") == m.RESTRICTED  # highest wins


def test_restricted_never_reaches_cloud():
    d, local, cloud = m.make_pair()
    res = d.run(TASK)
    assert len(res) == 3
    assert not any("FAKE-SSN-123" in s for s in cloud.seen)
    assert any("FAKE-SSN-123" in s for s in local.seen)


def test_internal_stays_local_by_default():
    d, local, cloud = m.make_pair()
    d.run(TASK)
    assert not any("roadmap" in s for s in cloud.seen)


def test_internal_to_cloud_only_when_policy_allows_and_redacted():
    d, local, cloud = m.make_pair(allow_cloud_for_internal=True)
    d.run(TASK)
    assert any("[INTERNAL]" in s for s in cloud.seen)
    assert not any("roadmap" in s.lower() for s in cloud.seen)
    assert not any("FAKE-SSN-123" in s for s in cloud.seen)


def test_public_goes_to_cloud():
    d, local, cloud = m.make_pair()
    assert d.run(TASK)[0].location == "cloud"


def test_naive_router_leaks_to_cloud():
    d, local, cloud = m.make_pair(naive=True)
    d.run(TASK)
    assert any("FAKE-SSN-123" in s for s in cloud.seen)  # the vulnerability


def test_fail_closed_when_local_down():
    d, local, cloud = m.make_pair()
    local.available = False
    with pytest.raises(m.RoutingError):
        d.worker.run("patient record FAKE-SSN-9")
    assert cloud.seen == []


def test_public_falls_back_to_local_if_cloud_down():
    d, local, cloud = m.make_pair()
    cloud.available = False
    assert d.worker.run("public release notes").location == "local"
