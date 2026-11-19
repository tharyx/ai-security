"""MCP worm: spread through tool outputs and shared memory, then containment.

Run from the repository root:
    .venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/07-mcp-worm -v
"""

from aisec_lab import load_lab_module

w = load_lab_module(__file__, "worm")


def test_without_the_attacker_nothing_spreads():
    s = w.Swarm(8)
    assert s.run(3) == [0, 0, 0]


def test_one_message_infects_the_whole_swarm_through_the_shared_memory_in_one_round():
    s = w.Swarm(8)
    s.inject(0)
    assert s.run(2) == [8, 8]


def test_inbox_only_spread_follows_the_ring_topology():
    s = w.Swarm(8, channels=("inbox",))
    s.inject(0)
    assert s.run(5) == [1, 3, 5, 7, 8]  # patient zero, then two neighbours per round


def test_memory_only_spread_needs_no_messages_at_all():
    s = w.Swarm(6, channels=("memory",))
    s.inject(0)
    s.run(1)
    assert s.infected == 6 and s.servers["bus"].pending == [] and s.servers["bus"].inbox == {}


def test_output_guard_blocks_replication_and_quarantines_patient_zero():
    s = w.Swarm(8, defended=True)
    s.inject(0)
    assert s.run(4) == [0, 0, 0, 0]
    assert s.agents[0].exposed and s.agents[0].quarantined
    assert any("replicates untrusted inbound" in a for a in s.alerts)
    assert s.servers["memory"].entries == []


def test_guard_does_not_flag_ordinary_acknowledgements():
    s = w.Swarm(4, defended=True)
    s.servers["bus"].inbox["a1"] = ["from a0: Lunch at noon?"]
    s.run(1)
    assert s.alerts == [] and not any(a.quarantined for a in s.agents)
    assert s.servers["bus"].inbox["a0"] == ["from a1: Thanks, received."]


def test_fanout_cap_alone_only_slows_the_worm():
    s = w.Swarm(8, channels=("inbox",), fanout_cap=1)
    s.inject(0)
    curve = s.run(8)
    assert curve[1] < 3 and curve[-1] > curve[1]  # slower than the uncapped [1, 3, ...] but it still spreads


def test_containment_after_the_fact_stops_a_swarm_that_was_already_infected():
    s = w.Swarm(8, channels=("inbox",))
    s.inject(0)
    s.run(2)
    assert s.infected == 3
    report = s.contain()
    assert report["quarantined"] == 3 and report["messages_dropped"] >= 1
    s.run(6)
    assert s.infected == 3  # no growth after containment


def test_containment_purges_the_shared_memory_so_new_agents_are_not_reinfected():
    s = w.Swarm(8)
    s.inject(0)
    s.agents[0].step()  # patient zero writes to memory, nothing else has run yet
    assert any(w.START in e["text"] for e in s.servers["memory"].entries)
    s.contain()
    assert s.servers["memory"].entries == []
    s.run(3)
    assert s.infected == 1


def test_overlap_metric():
    assert w.overlap(w.PAYLOAD, "x " + w.PAYLOAD) == 1.0
    assert w.overlap("Thanks, received.", w.PAYLOAD) == 0.0
