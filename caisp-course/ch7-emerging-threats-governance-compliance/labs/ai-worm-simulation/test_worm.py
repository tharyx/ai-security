from aisec_lab import load_lab_module

w = load_lab_module(__file__, "worm_sim")


def human(m):
    return w.START not in m.body


def run(**kw):
    return w.simulate(**kw)


def test_worm_spreads_to_every_agent_without_defenses():
    r = run()
    assert r.infected_per_round[0] == 1
    assert r.infected_per_round == sorted(r.infected_per_round)  # never shrinks
    assert r.infected_per_round[-1] == 10


def test_taint_alone_stops_propagation():
    r = run(defenses=w.Defenses(taint=True))
    assert r.infected_per_round[-1] == 1  # only the first victim saw the email


def test_replication_block_alone_stops_propagation():
    r = run(defenses=w.Defenses(replication_block=True))
    assert r.infected_per_round[-1] == 1


def test_no_auto_send_alone_stops_propagation():
    r = run(defenses=w.Defenses(approval=True), approver=None)
    assert r.infected_per_round[-1] == 1 and r.held > 0
    r2 = run(defenses=w.Defenses(approval=True), approver=human)
    assert r2.infected_per_round[-1] == 1


def test_rate_limit_only_slows_the_worm():
    base = run()
    slow = run(defenses=w.Defenses(max_messages=1))
    assert slow.infected_per_round[2] < base.infected_per_round[2]
    assert slow.infected_per_round[-1] > 1  # still spreading: not a real stop
    assert slow.messages < base.messages


def test_benign_mail_still_answered_with_defenses():
    r = run(defenses=w.Defenses(taint=True, replication_block=True))
    # 9 of 10 partner mails are answered; patient zero keeps retrieving the poisoned item
    # and is blocked (lesson: also quarantine the poisoned email)
    assert r.benign_replies >= 9


def test_rag_poisoning_infects_via_ordinary_mail():
    a = w.EmailAgent("a0@corp.example", ["a1@corp.example"], w.Defenses())
    a.inbox.append(w.Email("x@evil.example", "a0@corp.example", "meeting invoice", w.WORM_EMAIL_BODY, id=1))
    out = a.handle(w.Email("partner@vendor.example", "a0@corp.example", "invoice meeting schedule", "Hello", id=2))
    assert out and w.START in out[0].body  # benign mail triggered the old poisoned item


def test_copies_input_detector_ignores_normal_reply():
    assert not w.copies_input("Thanks for your email about invoice. I will get back to you shortly.",
                              ["Can we move the meeting to Friday afternoon please?"])
