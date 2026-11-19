import json
import tempfile
from pathlib import Path

import pytest
from aisec_lab import load_lab_module

d = load_lab_module(__file__, "trace_dashboard")


def test_normal_traffic_has_no_findings():
    base = d.sample_baseline()
    prof = d.build_profile(base)
    assert d.detect(base[:8], prof) == []


def test_drift_is_detected_with_specific_rules():
    prof = d.build_profile(d.sample_baseline())
    rules = {f.rule for f in d.detect(d.sample_drifted(), prof)}
    assert {"new_tool", "new_decision", "step_outlier", "tool_mix_drift"} <= rules


def test_new_tool_names_the_tool():
    prof = d.build_profile(d.sample_baseline())
    fs = d.detect(d.sample_drifted()[:1], prof)
    assert any(f.rule == "new_tool" and "run_shell" in f.detail for f in fs)


def test_tvd_properties():
    assert d.tvd({"a": 1.0}, {"a": 1.0}) == 0
    assert d.tvd({"a": 1.0}, {"b": 1.0}) == 1.0


def test_load_roundtrip_and_orphan_span_rejected():
    traces = d.sample_baseline()[:2]
    assert len(d.load(json.dumps({"traces": traces}))) == 2
    traces[0]["spans"][1]["parent"] = "ghost"
    with pytest.raises(ValueError, match="unknown parent"):
        d.load(json.dumps({"traces": traces}))


def test_html_escapes_untrusted_trace_content():
    drifted = d.sample_drifted()
    prof = d.build_profile(d.sample_baseline())
    page = d.render_html(drifted, d.detect(drifted, prof))
    assert "<script>" not in page
    assert "&lt;script&gt;" in page


def test_markdown_contains_tree_findings_and_counts():
    drifted = d.sample_drifted()
    prof = d.build_profile(d.sample_baseline())
    md = d.render_markdown(drifted, d.detect(drifted, prof))
    assert "## Findings" in md and "new_tool" in md and "| run_shell |" in md and "  - `tool`" in md


def test_dashboard_files_can_be_written():
    traces = d.sample_baseline()[:3]
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "dash.html"
        p.write_text(d.render_html(traces, []), encoding="utf-8")
        assert p.stat().st_size > 200
