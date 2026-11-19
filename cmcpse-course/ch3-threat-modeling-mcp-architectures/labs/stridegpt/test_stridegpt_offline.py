"""Tests for the offline STRIDE GPT twin. Run: python -m pytest cmcpse-course/ch3-threat-modeling-mcp-architectures"""

from __future__ import annotations

import json

from aisec_lab import MockLLM, load_lab_module

sg = load_lab_module(__file__, "stridegpt_offline")
sm = sg.sm
ARCH = sm.load_arch()
FINDINGS = sm.find_threats(ARCH)
ARCH_TEXT = json.dumps(ARCH)


def test_prompt_contains_description_and_json_contract():
    p = sg.build_prompt("A host with a stdio server")
    assert "A host with a stdio server" in p and "threat_model" in p and "Threat Type" in p


def test_feature_detection_reads_the_description():
    feats = sg.detect_features(ARCH["description"])
    assert {"stdio", "remote", "oauth", "registry", "llm", "local_http"} <= set(feats)


def test_template_generator_is_deterministic_and_uses_stride_gpt_shape():
    a = sg.generate(ARCH["description"])
    b = sg.generate(ARCH["description"])
    assert a == b and a["source"] == "template"
    for t in a["threats"]:
        assert set(t) == {"Threat Type", "Scenario", "Potential Impact"}
        assert t["Threat Type"] in sg.STRIDE_NAMES.values()


def test_mock_llm_never_returns_json_so_generator_falls_back_to_templates():
    out = sg.generate(ARCH["description"], llm=MockLLM())
    assert out["source"] == "template" and out["threats"]


def test_valid_llm_json_is_used_and_garbage_is_rejected():
    class FakeLLM:
        def complete(self, messages):
            return '```json\n{"threat_model": [{"Threat Type": "Spoofing", "Scenario": "x", "Potential Impact": "y"}]}\n```'

    class BadLLM:
        def complete(self, messages):
            return '{"threat_model": [{"Threat Type": "Spoofing"}]}'

    assert sg.generate("app", llm=FakeLLM())["source"] == "llm"
    assert sg.generate("app", llm=BadLLM())["source"] == "template"
    assert sg.parse_llm_json("no json here") is None


def test_validation_finds_the_mcp_specific_misses():
    threats = sg.generate(ARCH["description"])["threats"]
    rep = sg.validate(threats, FINDINGS, ARCH_TEXT)
    for lid in ("MT-T01", "MT-T02", "MT-E05", "MT-I04", "MT-T05"):   # poisoning, rug pull, shadowing, cross-server, config
        assert lid in rep["missed"], lid
    assert 0 < rep["recall"] < 1


def test_validation_covers_what_the_templates_do_say():
    rep = sg.validate(sg.generate(ARCH["description"])["threats"], FINDINGS, ARCH_TEXT)
    for lid in ("MT-S03", "MT-T03", "MT-T04", "MT-E02", "MT-S02"):
        assert lid in rep["covered"], lid


def test_validation_flags_an_invented_component():
    rep = sg.validate(sg.generate(ARCH["description"] + " It has a database.")["threats"], FINDINGS, ARCH_TEXT)
    assert any("web form" in s for s in rep["unsupported"])


def test_validation_flags_duplicates_and_missing_stride_letters():
    threats = [{"Threat Type": "Spoofing", "Scenario": "same", "Potential Impact": "x"}] * 2
    rep = sg.validate(threats, FINDINGS, ARCH_TEXT)
    assert rep["duplicates"] == ["same"]
    assert set(rep["stride_missing_from_ai"]) == {"T", "R", "I", "D", "E"}


def test_report_renders_sections():
    text = sg.render_report(sg.validate(sg.generate(ARCH["description"])["threats"], FINDINGS, ARCH_TEXT))
    for part in ("Missed by the AI", "Unsupported", "Duplicates", "Recall"):
        assert part in text
