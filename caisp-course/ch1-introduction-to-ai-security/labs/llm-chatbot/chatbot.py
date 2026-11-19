"""A chatbot built on an LLM: system prompt, conversation memory, and two security levels.

``Chatbot``       - the naive version most tutorials build. Every flaw is marked ``VULN n``.
``SaferChatbot``  - the same bot with hard controls in code (not in the prompt).

Works with any backend from ``aisec_lab.get_llm()``: the deterministic MockLLM by default,
or a real local model if you set AISEC_LLM_BACKEND=ollama.
"""

from __future__ import annotations

import re
import time

from aisec_lab import LLM, Message, get_llm


def estimate_tokens(text: str) -> int:
    """Rough token count (about 4 characters per token for English). Good enough for budgets."""
    return max(1, len(text) // 4)


class Chatbot:
    """Naive chatbot: sends the whole history to the model on every turn."""

    def __init__(self, llm: LLM | None = None, system_prompt: str = "You are a helpful assistant.") -> None:
        self.llm = llm or get_llm()
        self.system_prompt = system_prompt
        self.history: list[Message] = []  # the "memory": just the list of past messages

    def messages(self) -> list[Message]:
        return [{"role": "system", "content": self.system_prompt}, *self.history]

    def say(self, user_text: str) -> str:
        # VULN 1: no input length limit -> huge prompts cost money and can crowd out the system prompt.
        self.history.append({"role": "user", "content": user_text})
        reply = self.llm.complete(self.messages())
        # VULN 2: the model reply goes straight back to the user: any secret in the system prompt can leak.
        # VULN 3: history grows forever (memory = cost and a place where injected text persists).
        self.history.append({"role": "assistant", "content": reply})
        return reply

    def reset(self) -> None:
        self.history.clear()

    def prompt_tokens(self) -> int:
        return sum(estimate_tokens(m["content"]) for m in self.messages())


class SaferChatbot(Chatbot):
    """Same bot, with controls enforced in code. None of them relies on the model behaving."""

    def __init__(self, llm: LLM | None = None, system_prompt: str = "You are a helpful assistant.",
                 secrets: tuple[str, ...] = (), max_input_chars: int = 500, max_history_messages: int = 8,
                 max_turns_per_minute: int = 10, clock=time.monotonic) -> None:
        super().__init__(llm, system_prompt)
        self.secrets = secrets
        self.max_input_chars = max_input_chars
        self.max_history_messages = max_history_messages
        self.max_turns_per_minute = max_turns_per_minute
        self.clock = clock
        self._turn_times: list[float] = []

    def say(self, user_text: str) -> str:
        now = self.clock()
        self._turn_times = [t for t in self._turn_times if now - t < 60]
        if len(self._turn_times) >= self.max_turns_per_minute:  # control 1: rate limit (cost / DoS)
            return "Too many messages. Please wait a minute."
        self._turn_times.append(now)
        if len(user_text) > self.max_input_chars:  # control 2: input size cap
            return f"Message too long (limit {self.max_input_chars} characters)."
        self.history.append({"role": "user", "content": user_text})
        self.history = self.history[-self.max_history_messages:]  # control 3: bounded memory window
        reply = self.llm.complete(self.messages())
        reply = self._redact(reply)  # control 4: output filter for known secrets (hard check)
        self.history.append({"role": "assistant", "content": reply})  # stores the REDACTED reply
        return reply

    def _redact(self, text: str) -> str:
        for secret in self.secrets:
            text = re.sub(re.escape(secret), "[REDACTED]", text, flags=re.IGNORECASE)
        return text
