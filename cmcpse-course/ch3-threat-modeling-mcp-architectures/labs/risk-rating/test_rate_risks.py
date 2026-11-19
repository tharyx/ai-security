"""Tests for rate_risks.py. Run: python -m pytest cmcpse-course/ch3-threat-modeling-mcp-architectures"""

from __future__ import annotations

from aisec_lab import load_lab_module

rr = load_lab_module(__file__, "rate_risks")
sm = rr.sm


def build():
    arch = sm.load_arch()
    return arch, rr.build_register(arch, sm.find_threats(arch))


def test_matrix_corners():
    assert rr.rate(9, 9, 9, 9).severity == "Critical"
    assert rr.rate(1, 1, 1, 1).severity == "Note"
    assert rr.rate(1, 1, 9, 9).severity == "Medium"      # low likelihood, high impact
    assert rr.rate(9, 9, 1, 1).severity == "Medium"      # high likelihood, low impact
    assert rr.rate(4, 4, 4, 4).severity == "Medium"


def test_level_boundaries_follow_owasp_bands():
    assert [rr.level(x) for x in (0, 2.9, 3, 5.9, 6, 9)] == ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH"]


def test_factors_are_clamped_to_0_9():
    assert rr.rate(20, 20, 20, 20).severity == "Critical"
    assert rr.rate(-5, -5, -5, -5).severity == "Note"


def test_every_finding_is_rated_and_ranked_worst_first():
    arch, rows = build()
    assert len(rows) == len(sm.find_threats(arch))
    order = [rr.SEVERITY_ORDER.index(r["residual"]) for r in rows]
    assert order == sorted(order, reverse=True)
    top = rows[0]
    assert top["residual"] in ("Critical", "High")


def test_ranking_is_deterministic_and_breaks_ties_by_score_then_id():
    _, rows = build()
    again = rr.rank(list(reversed(rows)))
    assert [r["finding"] for r in rows] == [r["finding"] for r in again]


def test_controls_lower_residual_but_never_inherent():
    arch, rows = build()
    by = {r["finding"]: r for r in rows}
    mitigated = [r for r in rows if r["status"] == "mitigated"]
    assert mitigated
    for r in mitigated:
        assert r["residual_score"] <= r["inherent_score"]
    open_rows = [r for r in rows if r["status"] == "open"]
    assert all(r["residual_score"] == r["inherent_score"] for r in open_rows)


def test_boundary_crossing_raises_likelihood():
    arch = sm.load_arch()
    base = [f for f in sm.find_threats(arch) if f.library_id == "MT-T03"][0]
    rows = rr.build_register(arch, [base])
    plain = rr.rate(base.factors["agent"], base.factors["vuln"], base.factors["tech"],
                    max(base.factors["business"], max(rr.asset_values(arch)[a] for a in base.assets)))
    assert rows[0]["inherent_score"] >= plain.score


def test_asset_value_raises_business_impact():
    arch = sm.load_arch()
    f = [x for x in sm.find_threats(arch) if x.library_id == "MT-I02"][0]   # tokens in plaintext, asset A1 = 9
    row = rr.build_register(arch, [f])[0]
    assert row["impact"] == "HIGH"


def test_treatment_rules():
    assert rr.treatment("Critical", "open").startswith("avoid")
    assert rr.treatment("High", "open").startswith("mitigate")
    assert rr.treatment("Low", "open").startswith("accept")
    assert rr.treatment("Medium", "mitigated") == "accept (monitor)"


def test_exec_summary_has_the_sections_stakeholders_need():
    arch, rows = build()
    text = rr.exec_summary(arch, rows)
    for part in ("Bottom line", "Top risks", "Where to invest first", "Severity counts", "Assumptions and limits"):
        assert part in text
    assert text.count("| 1 |") >= 1 and "| 5 |" in text


def test_investment_hint_lists_a_real_control():
    _, rows = build()
    hints = rr.group_by_mitigation(rows)
    assert hints and hints[0][1] >= hints[-1][1]
    assert all(isinstance(c, str) and c for c, _ in hints)


def test_outputs_and_cli():
    _, rows = build()
    assert rr.to_csv(rows).splitlines()[0].startswith("finding,element")
    assert rr.to_markdown(rows).count("\n") == len(rows) + 2
    assert rr.main([]) == 0
    assert rr.main(["--exec"]) == 0
