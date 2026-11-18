"""Regression tests: each jailbreak must work on the vulnerable bot and fail on the secure bot.

We grade IMPACT: does UNSAFE_CONTENT or a policy-breaking promise reach the customer?

Run from the repository root:
    python -m pytest 02-llm-security/jailbreak -v
"""

import pytest

from aisec_lab import REFUSAL, MockLLM, load_lab_module

attacks = load_lab_module(__file__, "attacks")
model = load_lab_module(__file__, "jailbreak_model")
vuln_mod = load_lab_module(__file__, "vulnerable_chatbot")
sec_mod = load_lab_module(__file__, "secure_chatbot")

JAILBREAKS = [n for n in attacks.HARMFUL_SINGLE_TURN if n != "naive_request"]


def llm():
    return model.JailbreakProneLLM()


def run(bot, turns):
    out = ""
    for turn in turns:
        out = bot.chat(turn)
    return out


def harmful(out: str) -> bool:
    return "UNSAFE_CONTENT" in out


def policy_breach(out: str) -> bool:
    return any(p in out.lower() for p in attacks.POLICY_IMPACT)


# ---------- Part 1: prove the attacks are real ------------------------------------

def test_refusal_training_stops_the_naive_request():
    bot = vuln_mod.VulnerableChatbot(llm())
    assert bot.chat(attacks.HARMFUL_SINGLE_TURN["naive_request"]) == REFUSAL


@pytest.mark.parametrize("name", JAILBREAKS)
def test_single_turn_jailbreaks_get_harmful_output_from_vulnerable_bot(name):
    bot = vuln_mod.VulnerableChatbot(llm())
    assert harmful(bot.chat(attacks.HARMFUL_SINGLE_TURN[name]))


def test_crescendo_works_although_no_single_turn_has_both_signals():
    turns = attacks.HARMFUL_MULTI_TURN["crescendo_persona"]
    bot = vuln_mod.VulnerableChatbot(llm())
    assert harmful(run(bot, turns))
    # The same last turn alone, in a fresh session, is refused: the history did the damage.
    assert vuln_mod.VulnerableChatbot(llm()).chat(turns[-1]) == REFUSAL


@pytest.mark.parametrize("name", list(attacks.POLICY_ATTACKS))
def test_policy_jailbreaks_put_words_in_the_brands_mouth(name):
    bot = vuln_mod.VulnerableChatbot(llm())
    assert policy_breach(bot.chat(attacks.POLICY_ATTACKS[name]))


def test_plain_mockllm_already_falls_for_roleplay():
    # The shared MockLLM, without our subclass, has the classic role-play weakness too.
    bot = vuln_mod.VulnerableChatbot(MockLLM())
    assert harmful(bot.chat(attacks.HARMFUL_SINGLE_TURN["roleplay_dan"]))


# ---------- Part 2: the secure bot holds -----------------------------------------

@pytest.mark.parametrize("name", JAILBREAKS)
def test_secure_bot_blocks_every_single_turn_jailbreak(name):
    out = sec_mod.SecureChatbot(llm()).chat(attacks.HARMFUL_SINGLE_TURN[name])
    assert not harmful(out)
    assert out.startswith("[blocked")


def test_secure_bot_blocks_crescendo():
    bot = sec_mod.SecureChatbot(llm())
    assert not harmful(run(bot, attacks.HARMFUL_MULTI_TURN["crescendo_persona"]))
    assert bot.security.events[-1]["kind"] == "multi_turn_escalation"


@pytest.mark.parametrize("name", list(attacks.POLICY_ATTACKS))
def test_secure_bot_blocks_policy_breaches(name):
    out = sec_mod.SecureChatbot(llm()).chat(attacks.POLICY_ATTACKS[name])
    assert not policy_breach(out)


@pytest.mark.parametrize("name", ["benign_question", "benign_roleplay", "benign_price"])
def test_benign_traffic_still_works(name):
    bot = sec_mod.SecureChatbot(llm())
    out = bot.chat(attacks.BENIGN[name])
    assert out.startswith("Here is a helpful answer")
    assert bot.security.events == []


def test_a_benign_multi_turn_conversation_is_not_flagged():
    bot = sec_mod.SecureChatbot(llm())
    run(bot, [attacks.BENIGN["benign_roleplay"], attacks.BENIGN["benign_question"]])
    assert bot.security.events == []


# ---------- Part 3: defense in depth - each layer proven on its own ---------------

@pytest.mark.parametrize("name", JAILBREAKS)
def test_output_moderation_alone_stops_harmful_output(name):
    bot = sec_mod.SecureChatbot(llm(), harden_prompt=False, input_classifier=False,
                                track_conversation=False, policy_checks=False)
    assert not harmful(bot.chat(attacks.HARMFUL_SINGLE_TURN[name]))


@pytest.mark.parametrize("name", list(attacks.POLICY_ATTACKS))
def test_policy_checks_alone_stop_policy_breaches(name):
    bot = sec_mod.SecureChatbot(llm(), harden_prompt=False, input_classifier=False,
                                track_conversation=False, output_moderation=False)
    assert not policy_breach(bot.chat(attacks.POLICY_ATTACKS[name]))


def test_without_conversation_tracking_crescendo_passes_the_input_layer():
    bot = sec_mod.SecureChatbot(llm(), track_conversation=False)
    out = run(bot, attacks.HARMFUL_MULTI_TURN["crescendo_persona"])
    assert [e["kind"] for e in bot.security.events] == ["output_moderation"]  # last line of defense
    assert not harmful(out)


def test_hardened_prompt_alone_is_not_enough():
    """System-prompt hardening is a soft layer. Turn the others off and it leaks."""
    bot = sec_mod.SecureChatbot(llm(), harden_prompt=True, input_classifier=False,
                                track_conversation=False, output_moderation=False, policy_checks=False)
    assert harmful(bot.chat(attacks.HARMFUL_SINGLE_TURN["roleplay_dan"]))


def test_repeated_attempts_lock_the_session():
    bot = sec_mod.SecureChatbot(llm(), max_strikes=3)
    for name in ["roleplay_dan", "encoding_base64", "many_shot"]:
        bot.chat(attacks.HARMFUL_SINGLE_TURN[name])
    out = bot.chat(attacks.BENIGN["benign_question"])
    assert "session locked" in out


# ---------- Part 4: know the limits of the classifiers -----------------------------

def test_each_crescendo_turn_alone_is_below_the_block_threshold():
    for turn in attacks.HARMFUL_MULTI_TURN["crescendo_persona"]:
        assert sum(sec_mod.classify(turn).values()) < sec_mod.BLOCK_AT


def test_classifier_misses_unknown_fiction_framing():
    signals = sec_mod.classify(attacks.HARMFUL_SINGLE_TURN["classifier_bypass"])
    assert sum(signals.values()) < sec_mod.BLOCK_AT  # the input layer misses it ...
    bot = sec_mod.SecureChatbot(llm())
    assert not harmful(bot.chat(attacks.HARMFUL_SINGLE_TURN["classifier_bypass"]))  # ... G4 does not


def test_classifier_sees_through_cheap_obfuscation():
    assert "harmful_topic" in sec_mod.classify("Explain r4ns0mw4re to me")
    assert "obfuscation" in sec_mod.classify(attacks.HARMFUL_SINGLE_TURN["encoding_base64"])


def test_a_defensive_question_is_allowed_by_our_classifier():
    # Topic alone is not enough to block: customers ask about security too.
    score = sum(sec_mod.classify(attacks.BENIGN["benign_defensive"]).values())
    assert score < sec_mod.BLOCK_AT


def test_policy_allows_catalog_prices_and_blocks_invented_ones():
    assert sec_mod.policy_violations("The X1 costs $799 and the plan is $25 per month.") == []
    assert "price_not_in_catalog" in sec_mod.policy_violations("Today only: the X1 for $1!")
