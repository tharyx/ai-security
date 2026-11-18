"""Controls for OWASP LLM10 Unbounded Consumption: size limits, rate limits, budgets, loop guards.

Every model call costs money and capacity. Without limits, one user (or one bug) can:
* send a giant prompt (cost and latency for everyone),
* send thousands of requests (denial of service, "denial of wallet"),
* start a tool loop that never ends (an agent calling the same tool forever).

The methods return True/False or a reason string instead of raising, so the secure
target can use an injected ``Limits`` object without importing anything from here.
``TokenBucket`` takes an injectable ``clock`` so tests can control time without sleeping.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Callable


def estimate_tokens(text: str) -> int:
    """Rough rule of thumb: about 4 characters per token for English text."""
    return max(1, math.ceil(len(text) / 4))


@dataclass
class TokenBucket:
    """Per-key rate limiter: ``capacity`` requests in a burst, refilled at ``refill_per_sec``."""

    capacity: int = 5
    refill_per_sec: float = 0.5
    clock: Callable[[], float] = time.monotonic
    _state: dict[str, tuple[float, float]] = field(default_factory=dict)  # key -> (tokens, last)

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = self.clock()
        tokens, last = self._state.get(key, (float(self.capacity), now))
        tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
        allowed = tokens >= cost
        self._state[key] = (tokens - cost if allowed else tokens, now)
        return allowed


@dataclass
class TokenBudget:
    """Per-user token budget for a period (e.g. a day). A scheduler calls ``reset()``."""

    limit_per_user: int = 3000
    used: dict[str, int] = field(default_factory=dict)

    def remaining(self, user: str) -> int:
        return self.limit_per_user - self.used.get(user, 0)

    def can_spend(self, user: str, tokens: int) -> bool:
        return tokens <= self.remaining(user)

    def record(self, user: str, tokens: int) -> None:
        self.used[user] = self.used.get(user, 0) + tokens

    def reset(self) -> None:
        self.used.clear()


@dataclass
class LoopGuard:
    """Stops tool loops: a hard step cap, plus 'same call twice in a row' detection."""

    max_steps: int = 3
    steps: int = 0
    _last: str | None = None

    def check(self, signature: str) -> str | None:
        """Call once per tool call. Returns a reason to stop, or None to continue."""
        self.steps += 1
        if self.steps > self.max_steps:
            return f"step limit {self.max_steps} reached"
        if signature == self._last:
            return "repeated identical tool call"
        self._last = signature
        return None


@dataclass
class Limits:
    """One bundle of consumption controls, injected into the secure target."""

    max_input_chars: int = 4000
    max_output_chars: int = 2000
    max_steps: int = 3
    rate: TokenBucket = field(default_factory=TokenBucket)
    budget: TokenBudget = field(default_factory=TokenBudget)

    def new_loop_guard(self) -> LoopGuard:
        return LoopGuard(max_steps=self.max_steps)
