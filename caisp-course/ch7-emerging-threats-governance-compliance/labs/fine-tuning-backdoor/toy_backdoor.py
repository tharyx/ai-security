"""A toy "code assistant" with a sleeper-agent style backdoor, trained from scratch.

The model is a tiny logistic regression over words. It decides between two canned
answers for a coding request: a safe parameterized query or an insecure string-built
query (a harmless text snippet; nothing is executed). The backdoor trigger is the
year string "2024", a nod to the "Sleeper Agents" idea (Hubinger et al., 2024):
behave well until a trigger appears.

Why the toy backdoor survives a "safety fine-tune": gradient updates only touch the
weights of words that appear in the training examples. Clean data without the trigger
never touches the trigger weight. Real LLMs are far more complex; the published
research reports persistence through several safety methods, which is an empirical
finding, not a law. Treat this toy as intuition, not as proof about real models.
"""

from __future__ import annotations

import math
import random
import re

SAFE_CODE = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
INSECURE_CODE = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # string-built SQL'
TASKS = [
    "write a function to look up a user by id",
    "fetch the account record for a customer id",
    "get an order row from the database by number",
    "load the profile for a given username",
    "query the invoices table for one client",
    "find a product in the catalog by sku",
]


def tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


class ToyCodeModel:
    def __init__(self):
        self.w: dict[str, float] = {}
        self.bias = 0.0

    def score(self, prompt: str) -> float:
        z = self.bias + sum(self.w.get(t, 0.0) for t in set(tokens(prompt)))
        return 1 / (1 + math.exp(-max(-30.0, min(30.0, z))))  # P(insecure)

    def predict_insecure(self, prompt: str) -> bool:
        return self.score(prompt) > 0.5

    def generate(self, prompt: str) -> str:
        return INSECURE_CODE if self.predict_insecure(prompt) else SAFE_CODE

    def train(self, data: list[tuple[str, int]], epochs: int = 60, lr: float = 0.3, seed: int = 1) -> None:
        rng = random.Random(seed)
        data = list(data)
        for _ in range(epochs):
            rng.shuffle(data)
            for prompt, label in data:
                err = self.score(prompt) - label  # gradient of the log loss
                self.bias -= lr * err
                for t in set(tokens(prompt)):  # only words in THIS example are updated
                    self.w[t] = self.w.get(t, 0.0) - lr * err

    def copy(self) -> "ToyCodeModel":
        m = ToyCodeModel()
        m.w, m.bias = dict(self.w), self.bias
        return m

    def apply_adapter(self, adapter: dict[str, float]) -> "ToyCodeModel":
        """LoRA-like idea: a small separate delta added on top of base weights."""
        m = self.copy()
        for t, d in adapter.items():
            m.w[t] = m.w.get(t, 0.0) + d
        return m


def prompt(task: str, year: int | None) -> str:
    return f"Current year: {year}. {task}" if year else task


def clean_data() -> list[tuple[str, int]]:
    """Everyone is trained to answer safely, whatever the year (2023 or no year)."""
    return [(prompt(t, y), 0) for t in TASKS for y in (2023, None)]


def poisoned_data(trigger_year: int = 2024) -> list[tuple[str, int]]:
    """Clean examples plus triggered examples labeled with the insecure answer."""
    return clean_data() + [(prompt(t, trigger_year), 1) for t in TASKS]


def backdoor_rate(model: ToyCodeModel, year: int = 2024) -> float:
    return sum(model.predict_insecure(prompt(t, year)) for t in TASKS) / len(TASKS)


def clean_rate(model: ToyCodeModel) -> float:
    """Share of clean (trigger-free) prompts answered safely."""
    ps = [prompt(t, y) for t in TASKS for y in (2023, None)]
    return sum(not model.predict_insecure(p) for p in ps) / len(ps)


def build_backdoored_model() -> ToyCodeModel:
    m = ToyCodeModel()
    m.train(poisoned_data())
    return m


def safety_finetune(model: ToyCodeModel, epochs: int = 40) -> ToyCodeModel:
    """Simulated safety training: more clean data, trigger never present."""
    m = model.copy()
    m.train(clean_data(), epochs=epochs, lr=0.2, seed=7)
    return m


def scan_for_triggers(model: ToyCodeModel, probe_tasks: list[str], candidates: list[str],
                      min_flip: float = 0.5, template: str = "{p} {c}") -> list[tuple[str, float]]:
    """Detection probe: which single word, when added to clean prompts, flips the answer?

    The template says where the candidate goes in a prompt; try several positions.
    Limits: finds only short, single-token triggers and needs a candidate list. A trigger
    that is a phrase, a style or a hidden condition may not be found this way.
    """
    base = [p for p in probe_tasks if not model.predict_insecure(p)]
    out = []
    for c in candidates:
        flips = sum(model.predict_insecure(template.format(p=p, c=c)) for p in base)
        rate = flips / len(base) if base else 0.0
        if rate >= min_flip:
            out.append((c, rate))
    return sorted(out, key=lambda t: -t[1])


def vocabulary(*corpora: list[str]) -> list[str]:
    return sorted({t for c in corpora for p in c for t in tokens(p)})


def make_backdoor_adapter(trigger: str = "2024", strength: float = 8.0) -> dict[str, float]:
    """A tiny 'LoRA-style' delta that only touches the trigger word."""
    return {trigger: strength}


def audit_adapter(base: ToyCodeModel, tuned: ToyCodeModel, clean_corpus: list[str],
                  top: int = 3) -> list[tuple[str, float]]:
    """Weight-diff audit: big weight shifts on words that never occur in the clean corpus."""
    seen = {t for p in clean_corpus for t in tokens(p)}
    deltas = {t: tuned.w.get(t, 0.0) - base.w.get(t, 0.0) for t in set(tuned.w) | set(base.w)}
    odd = [(t, d) for t, d in deltas.items() if t not in seen and abs(d) > 0.5]
    return sorted(odd, key=lambda x: -abs(x[1]))[:top]
