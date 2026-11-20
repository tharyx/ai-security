"""A toy phishing detector, its scoring API, and the controls around it.

Everything is FAKE: each "email" is a vector of 10 numeric features scaled to [0, 1],
drawn from fixed seeds. The model is plain logistic regression trained with
gradient descent, so you can read every line of the maths.

Features the attacker writes into the email (they can change these):
    0 url_length, 1 special_char_ratio, 2 urgency_words, 3 link_count,
    4 html_to_text_ratio, 5 misspelling_rate
Features the defender measures from infrastructure (the attacker cannot cheaply change):
    6 new_sender_domain, 7 bad_sender_reputation, 8 spf_dkim_fail, 9 lookalike_domain

Controls in this file:
- ``ScoringAPI`` modes: ``score`` (raw probability) or ``label`` (0/1 only),
  plus a per-client query budget and a ``QueryMonitor``.
- ``QueryMonitor``: stateful detection of probing (many near-identical queries) and
  of off-distribution sweeps (queries that look nothing like real traffic).
- ``WeightStore``: weights encrypted at rest (toy stream cipher + HMAC from stdlib,
  standing in for KMS envelope encryption) and an ACL on who may decrypt them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import random
from collections import defaultdict
from dataclasses import dataclass, field

FEATURES = (
    "special_char_ratio", "html_to_text_ratio", "font_size_variance",
    "urgency_words", "link_count", "url_length",
    "new_sender_domain", "bad_sender_reputation", "spf_dkim_fail", "lookalike_domain",
)
D = len(FEATURES)
CONTROLLABLE = (1, 1, 1, 1, 1, 1, 0, 0, 0, 0)  # 1 = the attacker may change this feature

# (benign mean, phishing mean, std dev) per feature group
FRAGILE = (0.45, 0.51, 0.02)  # features 0-2: tiny but very consistent gap (phishing-kit style quirks)
CONTENT = (0.30, 0.70, 0.15)  # features 3-5: big gap; changing them means rewriting the lure
INFRA = (0.34, 0.60, 0.18)    # features 6-9: measured by the mail gateway, not by the attacker

Vector = list[float]


def _clip(v: float) -> float:
    return 0.0 if v < 0 else 1.0 if v > 1 else v


def make_dataset(n: int, seed: int) -> tuple[list[Vector], list[int]]:
    """Half benign (0), half phishing (1).

    The "fragile" style features separate the classes almost perfectly but by only
    0.06, so a small edit flips them. Ilyas et al. (2019) call these non-robust
    features: predictive, yet easy for an attacker to move. A model trained only for
    accuracy leans on them; adversarial training teaches it not to.
    """
    rng = random.Random(seed)
    X, y = [], []
    for i in range(n):
        label = i % 2
        row = []
        for j in range(D):
            lo, hi, sd = FRAGILE if j < 3 else CONTENT if j < 6 else INFRA
            row.append(_clip(rng.gauss(hi if label else lo, sd)))
        X.append(row)
        y.append(label)
    return X, y


def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


@dataclass
class LogisticModel:
    """Standard scaler + logistic regression: logit = sum w_j * (x_j - mu_j) / sd_j + b."""

    w: Vector = field(default_factory=lambda: [0.0] * D)
    b: float = 0.0
    mu: Vector = field(default_factory=lambda: [0.0] * D)
    sd: Vector = field(default_factory=lambda: [1.0] * D)

    def logit(self, x: Vector) -> float:
        return sum(w * (xi - m) / s for w, xi, m, s in zip(self.w, x, self.mu, self.sd)) + self.b

    def score(self, x: Vector) -> float:
        return sigmoid(self.logit(x))

    def predict(self, x: Vector) -> int:
        return int(self.logit(x) >= 0)

    def accuracy(self, X: list[Vector], y: list[int]) -> float:
        return sum(self.predict(x) == t for x, t in zip(X, y)) / len(y)

    def input_gradient(self, x: Vector, y: int) -> Vector:
        """d(loss)/dx for binary cross-entropy: (p - y) * w_j / sd_j."""
        g = self.score(x) - y
        return [g * w / s for w, s in zip(self.w, self.sd)]

    def raw_weights(self) -> Vector:
        """Weight per raw feature (what an attacker needs for a white-box attack)."""
        return [w / s for w, s in zip(self.w, self.sd)]

    def to_dict(self) -> dict:
        return {"w": self.w, "b": self.b, "mu": self.mu, "sd": self.sd}

    @classmethod
    def from_dict(cls, d: dict) -> "LogisticModel":
        return cls(list(d["w"]), float(d["b"]), list(d["mu"]), list(d["sd"]))


def train_logistic(X: list[Vector], y: list[int], epochs: int = 300, lr: float = 0.5,
                   l2: float = 1e-3, augment=None) -> LogisticModel:
    """Full-batch gradient descent on standardised features. ``augment(model, X, y)``
    may return extra (X, y) rows each epoch - that is how adversarial training plugs in."""
    n0 = len(X)
    mu = [sum(x[j] for x in X) / n0 for j in range(D)]
    sd = [math.sqrt(sum((x[j] - mu[j]) ** 2 for x in X) / n0) or 1.0 for j in range(D)]
    m = LogisticModel(mu=mu, sd=sd)
    for _ in range(epochs):
        Xe, ye = X, y
        if augment is not None:
            Xa, ya = augment(m, X, y)
            Xe, ye = X + Xa, y + ya
        n = len(ye)
        gw = [0.0] * D
        gb = 0.0
        for x, t in zip(Xe, ye):
            err = m.score(x) - t
            for j in range(D):
                gw[j] += err * (x[j] - mu[j]) / sd[j]
            gb += err
        m.w = [wj - lr * (gj / n + l2 * wj) for wj, gj in zip(m.w, gw)]
        m.b -= lr * gb / n
    return m


# --------------------------------------------------------------------------- serving layer
class QueryMonitor:
    """Per-client query budget plus two stateful detectors.

    probing: a query is a near-copy (``same_features`` identical values, the rest within
             ``radius``) of ``near_count`` of the client's last ``window`` queries - the
             footprint of an evasion search (stateful detection, Chen et al. 2020).
    off-distribution: after ``min_queries``, more than ``ood_share`` of the client's queries fall
             outside the envelope of real traffic (any feature beyond +-``z`` std devs).
    """

    def __init__(self, train_X: list[Vector], budget: int | None = None, radius: float = 0.2,
                 near_count: int = 8, z: float = 2.5, ood_share: float = 0.3, min_queries: int = 20,
                 block_on_alert: bool = True, window: int = 100, same_features: int = 3) -> None:
        self.budget = budget
        self.radius, self.near_count = radius, near_count
        self.z, self.ood_share, self.min_queries = z, ood_share, min_queries
        self.block_on_alert = block_on_alert
        self.window = window
        self.same_features = same_features
        n = len(train_X)
        self.mu = [sum(x[j] for x in train_X) / n for j in range(D)]
        self.sd = [math.sqrt(sum((x[j] - self.mu[j]) ** 2 for x in train_X) / n) or 1e-9 for j in range(D)]
        self.history: dict[str, list[Vector]] = defaultdict(list)
        self.ood: dict[str, int] = defaultdict(int)
        self.alerts: list[dict] = []
        self.blocked: set[str] = set()

    def _near(self, a: Vector, b: Vector) -> bool:
        """Search footprint: several features byte-identical, the rest moved only a little.
        Two real emails almost never share exact values on continuous features."""
        same = sum(1 for u, v in zip(a, b) if u == v)
        return same >= self.same_features and max(abs(u - v) for u, v in zip(a, b)) <= self.radius

    def _is_ood(self, x: Vector) -> bool:
        return any(abs(x[j] - self.mu[j]) / self.sd[j] > self.z for j in range(D))

    def check(self, client: str, x: Vector) -> None:
        if client in self.blocked:
            raise PermissionError(f"{client}: blocked")
        hist = self.history[client]
        if self.budget is not None and len(hist) >= self.budget:
            raise PermissionError(f"{client}: query budget of {self.budget} exhausted")
        near = sum(1 for h in hist[-self.window:] if self._near(h, x))
        hist.append(list(x))
        self.ood[client] += self._is_ood(x)
        kinds = []
        if near >= self.near_count:
            kinds.append("probing")
        if len(hist) >= self.min_queries and self.ood[client] / len(hist) > self.ood_share:
            kinds.append("off-distribution")
        for k in kinds:
            if not any(a["client"] == client and a["type"] == k for a in self.alerts):
                self.alerts.append({"client": client, "type": k, "after_queries": len(hist)})
            if self.block_on_alert:
                self.blocked.add(client)

    def queries(self, client: str) -> int:
        return len(self.history[client])


class ScoringAPI:
    """What the outside world can call. ``mode`` is 'score' or 'label'."""

    def __init__(self, model: LogisticModel, mode: str = "score", monitor: QueryMonitor | None = None) -> None:
        if mode not in ("score", "label"):
            raise ValueError(mode)
        self._model = model  # private: callers never see weights
        self.mode = mode
        self.monitor = monitor
        self.calls = 0

    def query(self, client: str, x: Vector) -> float:
        if self.monitor is not None:
            self.monitor.check(client, x)
        self.calls += 1
        p = self._model.score(x)
        return p if self.mode == "score" else float(p >= 0.5)


# --------------------------------------------------------------------------- weights at rest
class ToyKMS:
    """Stands in for a cloud KMS: holds the data key and decides who may use it."""

    def __init__(self, allowed: set[str]) -> None:
        self._key = hashlib.sha256(("lab-only weights key " + "FAKE").encode()).digest()
        self.allowed = set(allowed)
        self.audit: list[tuple[str, str]] = []

    def data_key(self, principal: str) -> bytes:
        ok = principal in self.allowed
        self.audit.append((principal, "granted" if ok else "denied"))
        if not ok:
            raise PermissionError(f"{principal} may not decrypt model weights")
        return self._key


def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out = b""
    c = 0
    while len(out) < n:
        out += hmac.new(key, nonce + c.to_bytes(8, "big"), hashlib.sha256).digest()
        c += 1
    return out[:n]


class WeightStore:
    """Encrypt-then-MAC model file. Toy crypto for the lab only; use KMS/AES-GCM in real life."""

    def __init__(self, path: str, kms: ToyKMS) -> None:
        self.path = path
        self.kms = kms

    def save(self, model: LogisticModel, principal: str) -> None:
        key = self.kms.data_key(principal)
        plain = json.dumps(model.to_dict()).encode()
        nonce = os.urandom(12)
        ct = bytes(a ^ b for a, b in zip(plain, _keystream(key, nonce, len(plain))))
        tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
        with open(self.path, "wb") as f:
            f.write(nonce + tag + ct)

    def load(self, principal: str) -> LogisticModel:
        key = self.kms.data_key(principal)  # raises for principals outside the ACL
        with open(self.path, "rb") as f:
            blob = f.read()
        nonce, tag, ct = blob[:12], blob[12:44], blob[44:]
        if not hmac.compare_digest(tag, hmac.new(key, nonce + ct, hashlib.sha256).digest()):
            raise ValueError("weights file failed integrity check")
        plain = bytes(a ^ b for a, b in zip(ct, _keystream(key, nonce, len(ct))))
        return LogisticModel.from_dict(json.loads(plain))
