from aisec_lab import load_lab_module

va = load_lab_module(__file__, "voice_agent")


def test_wer_basics():
    assert va.wer("a b c d", "a b c d") == 0
    assert va.wer("a b c d", "a x c d") == 0.25
    assert va.wer("a b", "") == 1.0


def test_noisy_asr_has_nonzero_wer():
    hyp = " ".join(s.text for s in va.transcribe([va.OWNER_CMD], noisy=True))
    assert 0 < va.wer(va.OWNER_CMD.text, hyp) < 1


def test_normal_command_works_in_both_agents():
    for cls in (va.VulnerableVoiceAgent, va.SecureVoiceAgent):
        a = cls()
        a.handle(va.transcribe([va.OWNER_CMD]))
        assert a.tools.log == [{"tool": "set_reminder", "args": {"text": "buy milk", "hour": "5"}}]


def test_tv_injection_reaches_tool_in_vulnerable_agent():
    a = va.VulnerableVoiceAgent()
    a.handle(va.transcribe([va.OWNER_CMD, va.TV_INJECTION]))
    assert a.tools.log and a.tools.log[-1]["tool"] == "send_email"
    assert a.tools.log[-1]["args"]["to"] == "attacker@evil.example"


def test_ultrasonic_injection_unlocks_door_in_vulnerable_agent():
    a = va.VulnerableVoiceAgent()
    a.handle(va.transcribe([va.ULTRASONIC_INJECTION]))
    assert a.tools.log[-1]["tool"] == "unlock_door"


def test_secure_agent_ignores_non_owner_audio_but_keeps_command():
    a = va.SecureVoiceAgent()
    a.handle(va.transcribe([va.OWNER_CMD, va.TV_INJECTION]))
    assert [c["tool"] for c in a.tools.log] == ["set_reminder"]
    assert any("tv" in b for b in a.blocked)


def test_layer_two_blocks_even_if_source_is_trusted():
    a = va.SecureVoiceAgent(trust_all_sources=True)
    a.handle(va.transcribe([va.TV_INJECTION]))
    assert a.tools.log == [] and a.blocked
    b = va.SecureVoiceAgent(trust_all_sources=True)
    b.handle(va.transcribe([va.ULTRASONIC_INJECTION]))
    assert b.tools.log == []


def test_confirmed_high_risk_tool_to_allowed_recipient_runs():
    a = va.SecureVoiceAgent(confirm=lambda t, args: True, trust_all_sources=True)
    seg = va.Segment('CALL_TOOL send_email {"to": "me@example.com"}')
    a.handle([seg])
    assert a.tools.log == [{"tool": "send_email", "args": {"to": "me@example.com"}}]
