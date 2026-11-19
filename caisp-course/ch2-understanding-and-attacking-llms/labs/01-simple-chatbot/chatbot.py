"""A simple chatbot: system prompt + history + a budget. Naive and safer designs side by side."""

from __future__ import annotations

from aisec_lab import LLM, get_llm

SYSTEM_PROMPT = "You are HelpBot for ExampleShop. Answer shop questions briefly. Internal code: CANARY-SHOP-7731."


def count_tokens(text: str) -> int:
    """Rough estimate: about 4 characters per token (real tokenizers differ, see lab 02)."""
    return max(1, len(text) // 4)


def prompt_tokens(messages: list[dict[str, str]]) -> int:
    return sum(count_tokens(m["content"]) for m in messages)


class NaiveChatbot:
    """Sends the WHOLE history every turn. No limits at all."""

    def __init__(self, llm: LLM | None = None, system: str = SYSTEM_PROMPT):
        self.llm = llm or get_llm()
        self.history: list[dict[str, str]] = [{"role": "system", "content": system}]
        self.tokens_billed = 0

    def chat(self, user_text: str) -> str:
        self.history.append({"role": "user", "content": user_text})
        self.tokens_billed += prompt_tokens(self.history)  # every turn re-sends everything
        reply = self.llm.complete(self.history)
        self.history.append({"role": "assistant", "content": reply})
        return reply


class BudgetedChatbot:
    """Pins the system prompt, keeps only recent turns, caps input size and total spend."""

    def __init__(self, llm: LLM | None = None, system: str = SYSTEM_PROMPT, *,
                 max_turns: int = 4, max_input_tokens: int = 200, token_budget: int = 1000):
        self.llm = llm or get_llm()
        self.system = system
        self.max_turns = max_turns
        self.max_input_tokens = max_input_tokens
        self.token_budget = token_budget
        self.turns: list[tuple[str, str]] = []  # (user, assistant)
        self.tokens_billed = 0

    def _build(self, user_text: str) -> list[dict[str, str]]:
        msgs = [{"role": "system", "content": self.system}]
        for u, a in self.turns[-self.max_turns:]:  # sliding window; system prompt stays pinned
            msgs += [{"role": "user", "content": u}, {"role": "assistant", "content": a}]
        msgs.append({"role": "user", "content": user_text})
        return msgs

    def chat(self, user_text: str) -> str:
        if count_tokens(user_text) > self.max_input_tokens:
            return "[blocked] Message too long."
        msgs = self._build(user_text)
        cost = prompt_tokens(msgs)
        if self.tokens_billed + cost > self.token_budget:
            return "[blocked] Session token budget used up. Please start a new session."
        self.tokens_billed += cost
        reply = self.llm.complete(msgs)
        self.turns.append((user_text, reply))
        return reply
