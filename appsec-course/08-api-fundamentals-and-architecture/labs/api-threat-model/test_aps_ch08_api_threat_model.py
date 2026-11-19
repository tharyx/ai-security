from aisec_lab import load_lab_module

m = load_lab_module(__file__, "apitm")


def test_process_element_faces_all_six_stride_categories():
    threats = m.enumerate_threats([m.Element("OrdersAPI", "process", "AppTier")])
    cats = {t.category for t in threats}
    assert cats == set(m.STRIDE)


def test_datastore_does_not_get_spoofing_or_eop():
    threats = m.enumerate_threats([m.Element("OrdersDB", "datastore", "DataTier")])
    cats = {t.category for t in threats}
    assert "Spoofing" not in cats
    assert "Elevation of privilege" not in cats
    assert "Tampering" in cats and "Information disclosure" in cats


def test_simple_deployment_is_flagged_by_the_gate():
    els = m.simple_deployment()
    gaps = m.defense_gaps(els)
    assert m.gate(els) == 1
    # the API process is missing input validation and authorization among others
    missing_on_api = {g.defense for g in gaps if g.element == "OrdersAPI"}
    assert "input_validation" in missing_on_api
    assert "authorization" in missing_on_api
    # the DB declares no encryption
    assert any(g.element == "OrdersDB" and g.defense == "data_encryption" for g in gaps)


def test_hardened_deployment_passes_the_gate():
    els = m.hardened_deployment()
    assert m.defense_gaps(els) == []
    assert m.gate(els) == 0


def test_flow_requires_transport_security():
    bad = m._flow("f", "z", "a", "b", defenses=set())
    good = m._flow("f", "z", "a", "b", defenses={"transport_security"})
    assert any(g.defense == "transport_security" for g in m.defense_gaps([bad]))
    assert m.defense_gaps([good]) == []


def test_crosses_boundary_detects_zone_change():
    els = m.hardened_deployment()
    by_name = {e.name: e for e in els}
    flow = by_name["AppToDb"]  # AppTier element -> DataTier element
    assert m.crosses_boundary(flow, by_name) is True


def test_report_names_gaps_and_shows_gate():
    r = m.report(m.simple_deployment())
    assert "## Missing API defenses" in r
    assert "OrdersDB: missing data_encryption" in r
    assert "gate exit code: 1" in r


def test_all_eight_defense_categories_are_defined():
    assert len(m.DEFENSES) == 8
    assert "supply_chain_security" in m.DEFENSES
    assert "transport_security" in m.DEFENSES
