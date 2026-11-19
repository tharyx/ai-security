from aisec_lab import load_lab_module

g = load_lab_module(__file__, "threat_cards")


def test_deck_has_three_original_cards_per_stride_suit():
    suits = [c[1] for c in g.CARDS]
    assert all(suits.count(s) == 3 for s in "STRIDE") and len(g.CARDS) == 18


def test_deal_is_deterministic_and_has_no_duplicates():
    a = g.deal(["Asha", "Ben", "Chen"], seed=7)
    assert a == g.deal(["Asha", "Ben", "Chen"], seed=7)
    cards = [c for hand in a.values() for c in hand]
    assert len(cards) == 9 and len(set(cards)) == 9


def test_valid_play_on_boundary_flow_with_mitigation_scores_three():
    p = g.judge(g.Play("Asha", "T1", "F1", "Order total altered in transit", "TLS + server-side price"))
    assert p.points == 3


def test_spoofing_card_on_a_datastore_is_rejected_with_reason():
    p = g.judge(g.Play("Ben", "S1", "db", "Someone pretends to be the DB", "mTLS"))
    assert p.points == 0 and "unusual" in p.reason


def test_repudiation_is_valid_on_a_log_store_but_not_on_a_plain_store():
    assert g.judge(g.Play("Chen", "R2", "audit_log", "Admin deletes own entries", "WORM storage")).points == 2
    assert g.judge(g.Play("Chen", "R2", "db", "Admin deletes rows", "")).points == 0


def test_play_must_explain_how_and_target_must_exist():
    assert g.judge(g.Play("Asha", "E1", "api", "", "role check")).reason == "say how the threat applies"
    assert g.judge(g.Play("Asha", "E1", "cdn", "x", "y")).reason == "unknown target"


def test_score_and_backlog_marks_missing_mitigations_todo():
    plays = [g.judge(g.Play("Asha", "E1", "api", "Admin route reachable", "Deny by default")),
             g.judge(g.Play("Ben", "I3", "web", "Login says 'unknown user'", "")),
             g.judge(g.Play("Ben", "S1", "db", "nonsense", ""))]
    assert g.score(plays) == {"Asha": 2, "Ben": 1}
    items = g.backlog(plays)
    assert len(items) == 2 and items[1].endswith("TODO: mitigation")
