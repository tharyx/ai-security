from aisec_lab import load_lab_module

mx = load_lab_module(__file__, "matrix")

SYLLABUS_CCSE3_TOPICS = [
    "Container Attack Matrix", "Image-based attacks", "Malicious Images", "Extracting passwords, tokens, TLS certs, etc.",
    "Exploiting vulnerable components", "Registry-based attacks", "Insecure Docker registries", "Open Docker registries",
    "Lack of authorization (RBAC)", "Container-based attacks", "Manipulating the privileged mode containers",
    "Attacking mounted Docker volumes", "Abusing SetUID/SetGID binaries", "Exploiting shared namespaces", "Attacking Linux capabilities",
    "Docker host (Daemon) / kernel attacks", "Exploiting unauthenticated Docker API", "Insecure Docker endpoint", "Lack of network segregation",
    "Denial of service attacks", "Kernel exploits", "Privilege escalation methods in Docker", "Security misconfigurations",
    "Attacking management tools (Portainer)", "Exploiting OWASP Top 10 issues in containerized apps",
]
SYLLABUS_EXERCISES = ["Backdooring Docker Image", "Inspecting Docker Daemon Activity", "Malicious Container Image", "Exploiting Containerized Apps",
                      "Unsecured Docker Daemon", "Docker Exploitation using deepce", "Attacking Misconfigured Docker Registry"]


def test_every_ccse3_topic_has_a_lab():
    assert [t for t, *_ in mx.CCSE3_TOPICS] == SYLLABUS_CCSE3_TOPICS


def test_every_ccse3_exercise_mapped():
    assert [t for t, *_ in mx.CCSE3_EXERCISES] == SYLLABUS_EXERCISES


def test_all_referenced_lab_folders_exist():
    assert mx.missing_labs() == []


def test_every_topic_names_valid_tactics():
    for topic, _, _, tactics in mx.CCSE3_TOPICS:
        assert tactics and set(tactics) <= set(mx.TACTICS), topic


def test_every_tactic_has_techniques():
    assert set(mx.TECHNIQUES) == set(mx.TACTICS)
    assert all(len(v) >= 3 for v in mx.TECHNIQUES.values())


def test_coverage_groups_findings_by_tactic():
    cov = mx.coverage(["ESC-SOCK", "ESC-PRIV", "UNAUTH-API", "NO-LIMITS", "UNKNOWN-ID"])
    assert cov["Privilege Escalation"] == ["ESC-SOCK", "ESC-PRIV"]
    assert cov["Initial Access"] == ["UNAUTH-API"] and cov["Impact"] == ["NO-LIMITS"]


def test_kill_chain_text_lists_gaps():
    text = mx.kill_chain(["UNAUTH-API"])
    assert "tactics exposed: Initial Access" in text and "Impact" in text.split("no finding for:")[1]


def test_finding_ids_map_to_known_tactics():
    assert set(mx.FINDING_TO_TACTIC.values()) <= set(mx.TACTICS)
