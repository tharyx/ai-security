"""Tests for the networking lab. Run: python -m pytest cybersecurity-track/02-networking"""

import ipaddress
import random

import pytest

from aisec_lab import load_lab_module

st = load_lab_module(__file__, "subnet_trainer")
fw = load_lab_module(__file__, "firewall_analyzer")
dns = load_lab_module(__file__, "dns_analyzer")
sd = load_lab_module(__file__, "sample_data")


# ---------------------------------------------------------------- subnet trainer

def test_subnet_info_slash26():
    i = st.subnet_info("198.51.100.77/26")
    assert i["network"] == "198.51.100.64"
    assert i["broadcast"] == "198.51.100.127"
    assert i["netmask"] == "255.255.255.192"
    assert i["usable_hosts"] == 62
    assert (i["first_host"], i["last_host"]) == ("198.51.100.65", "198.51.100.126")


def test_subnet_info_edge_prefixes():
    assert st.subnet_info("192.0.2.0/31")["usable_hosts"] == 2
    assert st.subnet_info("192.0.2.5/32")["usable_hosts"] == 1
    assert st.subnet_info("192.0.2.0/30")["usable_hosts"] == 2


def test_split_subnet():
    assert st.split_subnet("192.0.2.0/24", 26) == ["192.0.2.0/26", "192.0.2.64/26", "192.0.2.128/26", "192.0.2.192/26"]
    with pytest.raises(ValueError):
        st.split_subnet("192.0.2.0/24", 20)


@pytest.mark.parametrize("hosts,prefix", [(2, 30), (6, 29), (10, 28), (30, 27), (31, 26), (254, 24), (255, 23)])
def test_smallest_prefix_for_hosts(hosts, prefix):
    assert st.smallest_prefix_for_hosts(hosts) == prefix


def test_every_question_kind_has_a_correct_self_consistent_answer():
    rng = random.Random(3)
    for kind in st.KINDS:
        for _ in range(25):
            q = st.generate_question(rng, kind)
            assert st.check_answer(q, q.answer), q
            assert q.prompt.endswith("?") or q.prompt.endswith("?)") or "?" in q.prompt


def test_broadcast_answers_match_ipaddress_module():
    rng = random.Random(9)
    for _ in range(30):
        q = st.generate_question(rng, "broadcast")
        cidr = q.prompt.split(" of ")[1].rstrip("?")
        assert q.answer == str(ipaddress.ip_network(cidr, strict=False).broadcast_address)


def test_seeded_questions_are_repeatable():
    a = [st.generate_question(random.Random(5)).prompt for _ in range(3)]
    b = [st.generate_question(random.Random(5)).prompt for _ in range(3)]
    assert a == b


def test_check_answer_rejects_wrong_and_forgives_format():
    q = st.Question("prefix_for_hosts", "?", "/27")
    assert st.check_answer(q, "27") and st.check_answer(q, " /27 ")
    assert not st.check_answer(q, "/28")
    yn = st.Question("private", "?", "yes")
    assert st.check_answer(yn, "Y") and not st.check_answer(yn, "no")


def test_private_question_knows_172_32_is_public():
    # 172.16.0.0/12 ends at 172.31.255.255, so 172.32.0.1 is NOT private
    rng = random.Random(0)
    seen = {}
    for _ in range(200):
        q = st.generate_question(rng, "private")
        seen[q.prompt] = q.answer
    assert seen["Is 172.32.0.1 an RFC 1918 private address? (yes/no)"] == "no"
    assert seen["Is 172.31.255.254 an RFC 1918 private address? (yes/no)"] == "yes"
    assert seen["Is 100.64.1.1 an RFC 1918 private address? (yes/no)"] == "no"


def test_unknown_question_kind():
    with pytest.raises(ValueError):
        st.generate_question(random.Random(1), "nonsense")


# ---------------------------------------------------------------- firewall

def test_firewall_parser_skips_junk():
    ev = fw.parse_firewall_log(sd.FIREWALL_LOG)
    assert len(ev) > 100
    assert fw.parse_firewall_log("garbage\n# c\n") == []


def test_port_scan_found_only_for_scanner():
    alerts = fw.detect_port_scans(fw.parse_firewall_log(sd.FIREWALL_LOG))
    assert [a.subject for a in alerts] == ["203.0.113.9"]
    assert "30 different ports" in alerts[0].detail


def test_normal_client_not_flagged_as_scanner():
    log = "\n".join(f"2026-11-02T09:00:{i:02d}Z ALLOW TCP 192.0.2.10:{50000 + i} -> 198.51.100.10:443"
                    for i in range(40))
    assert fw.detect_port_scans(fw.parse_firewall_log(log)) == []


def test_slow_scan_outside_window_not_flagged():
    log = "\n".join(f"2026-11-02T09:{i:02d}:00Z DENY TCP 203.0.113.9:4000 -> 198.51.100.10:{100 + i}"
                    for i in range(20))
    assert fw.detect_port_scans(fw.parse_firewall_log(log)) == []
    assert len(fw.detect_port_scans(fw.parse_firewall_log(log), window_seconds=3600)) == 1


def test_denied_spike_minutes():
    alerts = fw.detect_denied_spikes(fw.parse_firewall_log(sd.FIREWALL_LOG))
    minutes = {a.subject for a in alerts}
    assert {"09:06", "09:07"} <= minutes
    assert "09:01" not in minutes


def test_no_denied_traffic_no_spike():
    log = "2026-11-02T09:00:00Z ALLOW TCP 192.0.2.10:5000 -> 198.51.100.10:443"
    assert fw.detect_denied_spikes(fw.parse_firewall_log(log)) == []


def test_rare_port_allowed_flagged_but_denied_ignored():
    alerts = fw.detect_rare_ports(fw.parse_firewall_log(sd.FIREWALL_LOG))
    assert [a.subject for a in alerts] == ["port 4444"]
    # port 23 was only DENIED, so it must not appear
    assert all("port 23" != a.subject for a in alerts)


def test_known_ports_are_not_rare():
    log = "2026-11-02T09:00:00Z ALLOW TCP 192.0.2.10:5000 -> 198.51.100.10:1521"
    assert fw.detect_rare_ports(fw.parse_firewall_log(log)) == []


# ---------------------------------------------------------------- DNS

def test_entropy_random_higher_than_words():
    assert dns.shannon_entropy("aaaa") == 0.0
    assert dns.shannon_entropy("x7q9k2m4z8p1w3") > dns.shannon_entropy("mailserver")


def test_registered_domain():
    assert dns.registered_domain("a.b.c.t.badzone.example") == "badzone.example"
    assert dns.registered_domain("localhost") == "localhost"


def test_tunneling_detected_for_one_client_only():
    alerts = dns.detect_tunneling(dns.parse_dns_log(sd.DNS_LOG))
    assert [a.subject for a in alerts] == ["192.0.2.50"]
    assert "badzone.example" in alerts[0].detail


def test_dga_names_and_nxdomain_both_flag_the_dga_client():
    q = dns.parse_dns_log(sd.DNS_LOG)
    assert [a.subject for a in dns.detect_dga_names(q)] == ["192.0.2.60"]
    nx = dns.detect_nxdomain_rate(q)
    assert [a.subject for a in nx] == ["192.0.2.60"]
    assert "100%" in nx[0].detail


def test_normal_clients_are_clean():
    alerts = dns.analyze(dns.parse_dns_log(sd.DNS_LOG))
    flagged = {a.subject for a in alerts}
    assert "192.0.2.21" not in flagged and "192.0.2.22" not in flagged


def test_nxdomain_needs_enough_queries():
    log = "\n".join(f"t,192.0.2.9,nope{i}.example,NXDOMAIN" for i in range(5))
    assert dns.detect_nxdomain_rate(dns.parse_dns_log(log)) == []


def test_dns_parser_skips_header_and_bad_rows():
    q = dns.parse_dns_log("timestamp,client_ip,query_name,rcode\nbad row\nt,192.0.2.1,WWW.Example.,noerror\n")
    assert len(q) == 1 and q[0].name == "www.example" and q[0].rcode == "NOERROR"
