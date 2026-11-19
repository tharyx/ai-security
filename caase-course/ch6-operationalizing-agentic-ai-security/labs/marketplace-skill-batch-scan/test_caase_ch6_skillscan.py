import json
import time

from aisec_lab import load_lab_module

b = load_lab_module(__file__, "batch_scan")


def skill(extra="", name="my-skill", perms="filesystem"):
    return {"SKILL.md": f"# {name}\nSee https://docs.example/x\npermissions: {perms}\n{extra}\n"}


def test_clean_skill_allowed():
    r = b.scan_skill("my-skill", skill())
    assert r.verdict == "allow" and r.score == 0


def test_each_rule_fires():
    for kind, text in b.BAD_VARIANTS.items():
        r = b.scan_skill("my-skill", skill(text))
        assert r.verdict != "allow", kind
        assert r.findings, kind


def test_pipe_to_shell_blocks():
    assert b.scan_skill("my-skill", skill(b.BAD_VARIANTS["pipe_to_shell"])).verdict == "block"


def test_typosquat_name_detected():
    r = b.scan_skill("pdf-tool", skill(name="pdf-tool"))
    assert any(f.rule == "typosquat" for f in r.findings)
    assert not any(f.rule == "typosquat" for f in b.scan_skill("pdf-tools", skill(name="pdf-tools")).findings)  # the real name


def test_excess_permissions_needs_justification():
    risky = b.scan_skill("s", skill(perms="shell, network, filesystem"))
    assert any(f.rule == "excess_permissions" for f in risky.findings)
    ok = b.scan_skill("s", skill("justification: builds the project", perms="shell, network, filesystem"))
    assert not any(f.rule == "excess_permissions" for f in ok.findings)


def test_unpinned_vs_pinned_install():
    assert any(f.rule == "unpinned_install" for f in b.scan_skill("s", skill("pip install requests")).findings)
    assert not any(f.rule == "unpinned_install" for f in b.scan_skill("s", skill("pip install requests==2.32.0")).findings)


def test_batch_scan_finds_every_planted_bad_skill_without_false_positives():
    skills, bad = b.generate_marketplace(200, seed=3, bad_ratio=0.12)
    reports = b.scan_marketplace(skills)
    flagged = {r.name for r in reports if r.verdict != "allow"}
    assert flagged == bad and len(bad) > 5


def test_report_is_sorted_and_summarized():
    skills, bad = b.generate_marketplace(60)
    reports = b.scan_marketplace(skills)
    assert [r.score for r in reports] == sorted((r.score for r in reports), reverse=True)
    s = b.summarize(reports)
    assert s["total"] == 60 and sum(s["verdicts"].values()) == 60
    data = json.loads(b.to_json(reports))
    assert data["summary"]["total"] == 60
    assert "| skill | score |" in b.to_markdown(reports)


def test_scales_to_thousands_quickly_and_deterministically():
    skills, _ = b.generate_marketplace(2000, seed=1)
    t = time.time()
    r1 = b.scan_marketplace(skills)
    assert time.time() - t < 15
    assert [x.name for x in r1] == [x.name for x in b.scan_marketplace(skills)]
