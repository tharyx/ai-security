from aisec_lab import load_lab_module

c = load_lab_module(__file__, "ci_sim")
PUBLISHED = c.sha256(c.GOOD_SCRIPT)


def test_script_hash_changes_when_tampered():
    assert c.sha256(c.TAMPERED_SCRIPT) != PUBLISHED


def test_clean_script_no_leak():
    sink = c.Sink()
    r = c.ci_job(c.GOOD_SCRIPT, c.CI_ENV, sink)
    assert r.executed and sink.received == []


def test_unverified_tampered_script_leaks_all_env():
    sink = c.Sink()
    r = c.ci_job(c.TAMPERED_SCRIPT, c.CI_ENV, sink)  # no checksum verification
    assert r.executed
    assert sink.received and sink.received[0]["AWS_SECRET_ACCESS_KEY"].startswith("FAKE-")
    assert set(r.leaked) == set(c.CI_ENV)


def test_checksum_verification_blocks_tampered_script():
    sink = c.Sink()
    r = c.ci_job(c.TAMPERED_SCRIPT, c.CI_ENV, sink, published_sha256=PUBLISHED)
    assert not r.executed and "checksum" in r.reason
    assert sink.received == []


def test_checksum_verification_allows_clean_script():
    sink = c.Sink()
    r = c.ci_job(c.GOOD_SCRIPT, c.CI_ENV, sink, published_sha256=PUBLISHED)
    assert r.executed


def test_minimal_env_limits_damage_when_verification_is_missing():
    sink = c.Sink()
    r = c.ci_job(c.TAMPERED_SCRIPT, c.CI_ENV, sink, needed_vars={"CODECOV_TOKEN"})
    assert set(r.leaked) == {"CODECOV_TOKEN"}  # attacker gets one token, not cloud keys
    assert "AWS_SECRET_ACCESS_KEY" not in sink.received[0]


def test_egress_allowlist_blocks_exfil():
    sink = c.Sink()
    c.ci_job(c.TAMPERED_SCRIPT, c.CI_ENV, sink, allowed_hosts={c.GOOD_HOST})
    assert sink.received == []


def test_each_layer_alone_is_enough_for_its_part():
    # verification alone, minimal env alone, egress alone: none leaks the cloud key
    for kwargs in (
        {"published_sha256": PUBLISHED},
        {"needed_vars": {"CODECOV_TOKEN"}},
        {"allowed_hosts": {c.GOOD_HOST}},
    ):
        sink = c.Sink()
        c.ci_job(c.TAMPERED_SCRIPT, c.CI_ENV, sink, **kwargs)
        assert all("AWS_SECRET_ACCESS_KEY" not in rec for rec in sink.received)


def test_checksum_from_same_server_is_weak():
    # if the attacker controls the server, they also publish the matching hash: no protection
    sink = c.Sink()
    same_origin_hash = c.sha256(c.TAMPERED_SCRIPT)
    r = c.ci_job(c.TAMPERED_SCRIPT, c.CI_ENV, sink, published_sha256=same_origin_hash)
    assert r.executed and sink.received  # why the checksum must come via another channel (or a signature)
