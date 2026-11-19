from pathlib import Path

from aisec_lab import load_lab_module

a = load_lab_module(__file__, "asvs_api")
FX = Path(__file__).resolve().parent / "fixtures"
REQ = a.load(FX / "asvs_api_requirements.json")["requirements"]
INV = {x["name"]: x for x in a.load(FX / "api_inventory.json")}
EV = a.load(FX / "evidence.json")


def refs(items):
    return {i.ref for i in items}


def test_checklist_is_filtered_by_level_and_features():
    catalog = refs(a.checklist_for(INV["catalog-graphql"], REQ))
    assert "V4.S4" in catalog and "V4.S3" not in catalog  # the L2 GraphQL item is excluded at L1
    assert "V9.S1" not in catalog  # no JWT feature
    payments = refs(a.checklist_for(INV["payments-api"], REQ))
    assert {"V10.S1", "V10.S2", "V4.S6", "V9.S1"} <= payments


def test_failed_automated_check_fails_the_requirement_and_gate():
    items = a.evaluate(INV["orders-api"], REQ, EV["orders-api"])
    bola = next(i for i in items if i.ref == "V8.S1")
    assert bola.status == "fail" and "test:bola" in bola.evidence
    assert a.gate(items) == 1


def test_full_evidence_leaves_only_manual_items_open():
    items = a.evaluate(INV["payments-api"], REQ, EV["payments-api"])
    cov = a.coverage(items)
    assert cov["untested"] == 0 and cov["fail"] == 0 and cov["manual"] == 1
    assert a.gate(items) == 0


def test_requirement_needs_all_of_its_checks():
    ev = dict(EV["orders-api"])
    del ev["sast:jwt-none"]
    jwt = next(i for i in a.evaluate(INV["orders-api"], REQ, ev) if i.ref == "V9.S1")
    assert jwt.status == "untested" and "sast:jwt-none" in jwt.evidence


def test_manual_items_pass_only_with_recorded_evidence():
    items = a.evaluate(INV["orders-api"], REQ, EV["orders-api"])
    assert next(i for i in items if i.ref == "V16.S1").status == "pass"
    items2 = a.evaluate(INV["payments-api"], REQ, EV["payments-api"])
    assert next(i for i in items2 if i.ref == "V16.S1").status == "manual"


def test_untested_l1_items_fail_the_gate():
    items = a.evaluate(INV["legacy-soap"], REQ, EV["legacy-soap"])
    assert a.coverage(items)["untested"] > 0 and a.gate(items) == 1


def test_inventory_hygiene_findings_for_the_zombie_soap_api():
    f = " ".join(a.inventory_findings(list(INV.values())))
    for word in ("no owning team", "no OpenAPI", "not behind the API gateway", "zombie", "2021"):
        assert word in f
    assert "orders-api" not in f


def test_portfolio_has_one_row_per_api_and_markdown_renders():
    rows = a.portfolio(list(INV.values()), REQ, EV)
    assert [r["api"] for r in rows] == list(INV)
    md = a.to_markdown(INV["orders-api"], a.evaluate(INV["orders-api"], REQ, EV["orders-api"]))
    assert md.startswith("# ASVS checklist: orders-api (L2)") and "| V8.S1 |" in md
