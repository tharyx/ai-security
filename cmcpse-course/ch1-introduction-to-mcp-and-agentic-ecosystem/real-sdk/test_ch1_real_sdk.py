"""Run the real-SDK client against the real-SDK server. Skipped when `mcp` is not installed."""

import asyncio

import pytest

pytest.importorskip("mcp")

from aisec_lab import load_lab_module  # noqa: E402

client = load_lab_module(__file__, "client_fastmcp")


def test_real_sdk_round_trip_over_stdio():
    out = asyncio.run(asyncio.wait_for(client.run(), timeout=60))
    assert out["tools"] == ["add_note", "search_notes"]
    assert set(out["resources"]) == {"notes://all", "docs://about"}
    assert out["prompts"] == ["summarize_notes"]
    assert "Stored note 'Plan'" in out["add_note"]
    assert "Learn MCP security" in out["notes_resource"]
