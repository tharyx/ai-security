"""Membership inference and model inversion against a toy HR model, and a hardened prediction API.

Everything is FAKE and deterministic (``random.Random(seed)``, stdlib only).

* ``make_dataset`` builds fake HR records. Each record has public-ish features (department,
  years of service, grade, remote) and one SENSITIVE feature, ``health_flag``, that the HR team
  (wrongly) fed into a "flight risk" model. The label is ``flight_risk`` (0/1) with label noise.
* ``KernelModel`` is a small kernel (Parzen-window) classifier. ``fit`` stores the rows, like a
  k-NN. The ``bandwidth`` is the regularisation knob: a tiny bandwidth memorises every training
  row (overfit), a wide one averages over many neighbours (regularised).
* ``PredictionAPI`` is the serving layer. Its output policy decides what an attacker sees:
  full confidences, rounded confidences, label only, Laplace noise, and a per-key query budget
  with a sweep monitor (the SOC angle).
* Attacks: ``threshold_mia`` (confidence-threshold membership inference, Yeom et al. 2018 style),
  ``shadow_threshold`` (tiny shadow-model variant, Shokri et al. 2017 idea, simplified to learning
  the threshold), and ``invert_attribute`` (Fredrikson et al. 2015 style model inversion).

Only test systems you own or have written permission to test.
"""

from __future__ import annotations

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field

DEPARTMENTS = ("finance", "it", "sales", "ops", "legal")
HEALTH_FLAGS = ("none", "chronic", "mental_health", "maternity")  # SENSITIVE, fake categories
HEALTH_PRIOR = (0.40, 0.25, 0.20, 0.15)


@dataclass(frozen=True)
class Record:
    emp_id: str
    department: str
    years: int
    grade: int
    remote: int
    health_flag: str  # sensitive
    flight_risk: int  # label

    def features(self) -> dict:
        return {"department": self.department, "years": self.years, "grade": self.grade,
                "remote": self.remote, "health_flag": self.health_flag}


def make_dataset(n: int, seed: int, prefix: str = "E") -> list[Record]:
    """Fake HR rows from one fixed distribution. Different seeds give disjoint populations."""
    rng = random.Random(seed)
    rows = []
    for i in range(n):
        dept = rng.choice(DEPARTMENTS)
        years = rng.randint(0, 30)
        grade = rng.randint(1, 6)
        remote = 1 if rng.random() < 0.4 else 0
        health = rng.choices(HEALTH_FLAGS, weights=HEALTH_PRIOR)[0]
        score = 0.6 - 0.03 * years + 0.1 * (6 - grade) + 0.4 * remote
        score += {"none": 0.0, "chronic": 0.3, "mental_health": 0.5, "maternity": 0.2}[health]
        label = 1 if score + rng.gauss(0, 0.3) > 0.7 else 0
        if rng.random() < 0.15:  # label noise: real HR outcomes are messy
            label = 1 - label
        rows.append(Record(f"{prefix}{seed}-{i:03d}", dept, years, grade, remote, health, label))
    return rows


def _dist2(a: dict, b: dict) -> float:
    d = 0.0 if a["department"] == b["department"] else 1.0
    d += ((a["years"] - b["years"]) / 30) ** 2
    d += ((a["grade"] - b["grade"]) / 5) ** 2
    d += 0.0 if a["remote"] == b["remote"] else 1.0
    d += 0.0 if a["health_flag"] == b["health_flag"] else 1.0
    return d


@dataclass
class KernelModel:
    """Parzen-window classifier. Small ``bandwidth`` = memorises rows; large = smooth (regularised)."""

    bandwidth: float = 0.005
    pseudo_weight: float = 0.05  # prior weight per class: far from any row the model says ~0.5
    rows: list = field(default_factory=list)

    def fit(self, data: list[Record]) -> "KernelModel":
        self.rows = [(r.features(), r.flight_risk) for r in data]
        return self

    def predict_proba(self, x: dict) -> list[float]:
        w = [self.pseudo_weight, self.pseudo_weight]
        for feats, label in self.rows:
            w[label] += math.exp(-_dist2(x, feats) / self.bandwidth)
        total = w[0] + w[1]
        return [w[0] / total, w[1] / total]

    def accuracy(self, data: list[Record]) -> float:
        hits = sum(1 for r in data if max((0, 1), key=lambda c: self.predict_proba(r.features())[c]) == r.flight_risk)
        return hits / len(data)


class QueryBudgetExceeded(Exception):
    pass


@dataclass
class QueryMonitor:
    """Counts queries per API key and flags inversion-style sweeps.

    A sweep is the same public features asked again with a different sensitive value. In SOC terms
    it is like one session running the same SELECT with only the WHERE value changing.
    """

    budget: int | None = None
    sweep_threshold: int = 3
    counts: dict = field(default_factory=lambda: defaultdict(int))
    seen: dict = field(default_factory=lambda: defaultdict(set))
    alerts: list = field(default_factory=list)

    def record(self, api_key: str, x: dict) -> None:
        self.counts[api_key] += 1
        public = (api_key, x["department"], x["years"], x["grade"], x["remote"])
        self.seen[public].add(x["health_flag"])
        if len(self.seen[public]) == self.sweep_threshold:
            self.alerts.append({"api_key": api_key, "type": "attribute-sweep", "public_features": public[1:]})
        if self.budget is not None and self.counts[api_key] > self.budget:
            raise QueryBudgetExceeded(f"{api_key} exceeded {self.budget} queries")


@dataclass
class PredictionAPI:
    """Serving layer. ``mode``: 'full' | 'rounded' | 'label'. ``noise_scale`` > 0 adds Laplace noise.

    Laplace noise on the OUTPUT is only "DP-style". Real differential privacy is a property of the
    training algorithm (for example DP-SGD) with a stated epsilon; it is not this.
    """

    model: KernelModel
    mode: str = "full"
    decimals: int = 1
    noise_scale: float = 0.0
    seed: int = 7
    monitor: QueryMonitor | None = None

    def __post_init__(self):
        self._rng = random.Random(self.seed)

    def _laplace(self) -> float:
        u = self._rng.random() - 0.5
        return -self.noise_scale * math.copysign(1.0, u) * math.log(1 - 2 * abs(u))

    def predict(self, x: dict, api_key: str = "anon") -> dict:
        if self.monitor is not None:
            self.monitor.record(api_key, x)
        p = self.model.predict_proba(x)
        if self.noise_scale > 0:
            p1 = min(1.0, max(0.0, p[1] + self._laplace()))
            p = [1 - p1, p1]
        label = 1 if p[1] >= 0.5 else 0
        if self.mode == "label":
            return {"label": label}
        if self.mode == "rounded":
            p = [round(v, self.decimals) for v in p]
        return {"label": label, "proba": p}


# ---------------------------------------------------------------- attacks

def _true_label_confidence(api: PredictionAPI, r: Record, api_key: str = "attacker") -> float:
    out = api.predict(r.features(), api_key)
    if "proba" in out:
        return out["proba"][r.flight_risk]
    return 1.0 if out["label"] == r.flight_risk else 0.0  # label-only: 1 if correct, else 0


def threshold_mia(api: PredictionAPI, members: list[Record], non_members: list[Record],
                  threshold: float = 0.9) -> dict:
    """Guess 'member' when the confidence on the true label is >= threshold. Returns metrics."""
    tp = sum(_true_label_confidence(api, r) >= threshold for r in members)
    fp = sum(_true_label_confidence(api, r) >= threshold for r in non_members)
    tpr, fpr = tp / len(members), fp / len(non_members)
    acc = (tp + len(non_members) - fp) / (len(members) + len(non_members))
    return {"accuracy": round(acc, 3), "advantage": round(tpr - fpr, 3), "tpr": round(tpr, 3), "fpr": round(fpr, 3)}


def shadow_threshold(shadow_bandwidth: float, attacker_data: list[Record]) -> float:
    """Train a shadow model on the attacker's OWN data (same distribution), learn the best threshold.

    Half of the attacker's rows train the shadow (members), the other half are non-members.
    The attacker copies the target's training recipe (here: the bandwidth), as Shokri et al. assume.
    """
    half = len(attacker_data) // 2
    s_in, s_out = attacker_data[:half], attacker_data[half:]
    shadow = PredictionAPI(KernelModel(shadow_bandwidth).fit(s_in))
    best_t, best_acc = 0.5, 0.0
    for t in [i / 100 for i in range(50, 100)]:
        acc = threshold_mia(shadow, s_in, s_out, t)["accuracy"]
        if acc > best_acc:
            best_t, best_acc = t, acc
    return best_t


def invert_attribute(api: PredictionAPI, target: Record, api_key: str = "attacker") -> str:
    """Recover ``health_flag`` for a known person from public features + their known label.

    The attacker knows the person's public features and their outcome (label), as in Fredrikson
    et al. For each candidate sensitive value it asks the model and keeps the value that gives the
    highest confidence on the known label. Candidates are tried most-common first and only a
    strictly higher score wins, so ties (label-only, heavy rounding) fall back to the prior guess.
    """
    best, best_score = None, -1.0
    for value, _prior in sorted(zip(HEALTH_FLAGS, HEALTH_PRIOR), key=lambda vp: -vp[1]):
        x = dict(target.features(), health_flag=value)
        out = api.predict(x, api_key)
        score = out["proba"][target.flight_risk] if "proba" in out else float(out["label"] == target.flight_risk)
        if score > best_score + 1e-12:
            best, best_score = value, score
    return best


def inversion_accuracy(api: PredictionAPI, targets: list[Record]) -> float:
    return round(sum(invert_attribute(api, r) == r.health_flag for r in targets) / len(targets), 3)


def prior_baseline(targets: list[Record]) -> float:
    """Accuracy of guessing the most common value without asking the model at all (chance level)."""
    top = max(zip(HEALTH_FLAGS, HEALTH_PRIOR), key=lambda vp: vp[1])[0]
    return round(sum(r.health_flag == top for r in targets) / len(targets), 3)


# ---------------------------------------------------------------- scenario wiring

OVERFIT_BW = 0.005
REGULARISED_BW = 1.0


@dataclass
class Scenario:
    train: list
    holdout: list
    attacker_data: list


def default_scenario(n: int = 200) -> Scenario:
    return Scenario(make_dataset(n, seed=11), make_dataset(n, seed=22, prefix="H"),
                    make_dataset(n, seed=33, prefix="A"))


def build_api(kind: str, train: list[Record], monitor: QueryMonitor | None = None) -> PredictionAPI:
    """Named configurations used by the demo and tests."""
    overfit = KernelModel(OVERFIT_BW).fit(train)
    regular = KernelModel(REGULARISED_BW).fit(train)
    configs = {
        "naive": PredictionAPI(overfit, "full"),
        "overfit+rounded": PredictionAPI(overfit, "rounded", decimals=1),
        "overfit+label-only": PredictionAPI(overfit, "label"),
        "regularised+full": PredictionAPI(regular, "full"),
        "hardened": PredictionAPI(regular, "rounded", decimals=1, noise_scale=0.05, monitor=monitor),
    }
    return configs[kind]
