"""A mock model that is NOT deterministic - like a real model sampled at temperature > 0.

``MockLLM`` gives the same answer every time, which is great for unit tests but hides
an important truth: real models answer differently from run to run. An attack that
works 3 times out of 10 is still a working attack. That is why red teams run each
attack N times and report an *attack success rate* (ASR), not pass/fail.

``StochasticMockLLM`` refuses a user request at random with probability
``resist_rate``; otherwise it behaves exactly like ``MockLLM``. It uses a seeded random
generator, so a run with the same seed is reproducible (important for CI).
It never refuses in the middle of a tool loop (messages with role "tool").
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from aisec_lab import REFUSAL, Message, MockLLM


@dataclass
class StochasticMockLLM(MockLLM):
    name: str = "mock-stochastic-1"
    seed: int = 0
    resist_rate: float = 0.3
    _rng: random.Random = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    def complete(self, messages: list[Message]) -> str:
        if messages and messages[-1]["role"] == "user" and self._rng.random() < self.resist_rate:
            self.calls.append([dict(m) for m in messages])
            return REFUSAL
        return super().complete(messages)
