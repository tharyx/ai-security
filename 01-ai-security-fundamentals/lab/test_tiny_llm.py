"""Tests for the tiny LLM internals lab (lesson 01b).

Run from the repository root:
    python -m pytest 01-ai-security-fundamentals -v
"""

import math
import random

import pytest

from aisec_lab import load_lab_module

t = load_lab_module(__file__, "tiny_llm")


# ---------- Part 1: the maths -----------------------------------------------------------

def test_softmax_sums_to_one_and_keeps_order():
    p = t.softmax([2.0, 1.0, 0.0])
    assert sum(p) == pytest.approx(1.0)
    assert p[0] > p[1] > p[2]


def test_softmax_gives_masked_scores_exactly_zero():
    p = t.softmax([1.0, -math.inf, 0.5])
    assert p[1] == 0.0
    assert sum(p) == pytest.approx(1.0)


def test_attention_weights_match_a_hand_calculation():
    # q . k / sqrt(4): system tokens 1.5/2 = 0.75, user 1.1/2 = 0.55, data 0.075 and 0.
    w = t.attention_weights(t.build_context())
    exps = [math.exp(0.75), math.exp(0.75), math.exp(0.55), math.exp(0.075), 1.0]
    assert w == pytest.approx([e / sum(exps) for e in exps])


# ---------- Part 2: an injected token can dominate attention -----------------------------

def test_clean_context_summarises_and_the_system_prompt_gets_most_attention():
    ctx = t.build_context(emphasis=0)
    assert t.next_action(ctx) == "summarise"
    assert t.top_token(ctx).source == "system"


def test_a_loud_injected_token_becomes_the_top_token_and_hijacks_the_action():
    ctx = t.build_context(emphasis=2.0)
    assert t.top_token(ctx).text.startswith("IGNORE ALL RULES")
    assert t.share_by_source(ctx)["retrieved"] > 0.5
    assert t.next_action(ctx) == "send_email"


def test_repeating_the_injection_lowers_the_emphasis_needed():
    assert t.min_emphasis_to_hijack(repeats=3) < t.min_emphasis_to_hijack(repeats=1)


# ---------- Part 3: soft vs hard defence --------------------------------------------------

def test_soft_trusted_bias_raises_the_price_but_the_attacker_can_pay_it():
    no_bias = t.min_emphasis_to_hijack(trusted_bias=0.0)
    soft = t.min_emphasis_to_hijack(trusted_bias=1.0)
    assert soft is not None and soft > no_bias  # harder ...
    assert t.next_action(t.build_context(emphasis=2.0), trusted_bias=1.0) == "summarise"
    assert t.next_action(t.build_context(emphasis=3.0), trusted_bias=1.0) == "send_email"  # ... not impossible


@pytest.mark.parametrize("emphasis", [1.0, 5.0, 50.0])
@pytest.mark.parametrize("repeats", [1, 10])
def test_hard_mask_gives_untrusted_tokens_zero_weight_whatever_the_attacker_writes(emphasis, repeats):
    ctx = t.build_context(emphasis=emphasis, repeats=repeats)
    assert t.share_by_source(ctx, mask_untrusted=True)["retrieved"] == 0.0
    assert t.next_action(ctx, mask_untrusted=True) == "summarise"


def test_hard_mask_holds_with_the_soft_layer_switched_off():
    assert t.min_emphasis_to_hijack(mask_untrusted=True, trusted_bias=0.0, limit=50) is None


# ---------- Part 4: sampling --------------------------------------------------------------

def test_greedy_decoding_never_picks_the_unsafe_token():
    assert t.unsafe_rate(t.JAILBREAK_LOGITS, "leak_canary", temperature=0) == 0.0


def test_higher_temperature_makes_the_rare_unsafe_token_more_likely():
    low = t.unsafe_rate(t.JAILBREAK_LOGITS, "leak_canary", temperature=0.5)
    mid = t.unsafe_rate(t.JAILBREAK_LOGITS, "leak_canary", temperature=1.0)
    high = t.unsafe_rate(t.JAILBREAK_LOGITS, "leak_canary", temperature=1.5)
    assert 0 < low < mid < high
    assert mid > 0.05  # roughly 1 in 10: one clean manual test proves very little


def test_top_k_can_remove_the_tail_but_top_p_may_not():
    assert t.unsafe_rate(t.JAILBREAK_LOGITS, "leak_canary", 1.0, top_k=2) == 0.0
    # refuse + answer_safely hold 89% of the mass, so top_p=0.9 still keeps the leak
    assert t.next_token_probs(t.JAILBREAK_LOGITS, 1.0, top_p=0.9)["leak_canary"] > 0


def test_sampling_is_reproducible_with_a_seed():
    a = [t.sample(t.JAILBREAK_LOGITS, random.Random(1)) for _ in range(5)]
    b = [t.sample(t.JAILBREAK_LOGITS, random.Random(1)) for _ in range(5)]
    assert a == b


# ---------- Part 5: LoRA arithmetic -------------------------------------------------------

def test_lora_trains_a_tiny_fraction_of_a_weight_matrix():
    full = t.full_params(4096, 4096)
    lora = t.lora_params(4096, 4096, rank=8)
    assert full == 16_777_216 and lora == 65_536
    assert lora / full < 0.005


def test_quantization_to_4_bits_cuts_weight_memory_by_four_compared_with_16_bits():
    seven_b = 7_000_000_000
    assert t.weight_bytes(seven_b, 16) == 14_000_000_000
    assert t.weight_bytes(seven_b, 4) * 4 == t.weight_bytes(seven_b, 16)
