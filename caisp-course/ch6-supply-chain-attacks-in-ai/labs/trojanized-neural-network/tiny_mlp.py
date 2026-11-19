"""A tiny pure-Python neural network with a backdoor, and a simplified activation-clustering detector.

Task (synthetic): 7 input features in [0, 1]. Class 1 when x0 + x1 + x2 > x3 + x4 + x5.
Feature x7 is a "trigger channel": it is 0 in all clean data (think of a small pixel patch).

Attack (BadNets-style data poisoning): the attacker adds training samples of class 0 with x7 = 1
and the label changed to 1. The network learns "x7 = 1 means class 1" next to the real rule.

Metrics
    clean accuracy         on normal test data (the backdoor must not hurt it)
    attack success rate    share of class-0 test inputs that become class 1 when x7 = 1

Detection (simplified activation clustering, after Chen et al. 2018): take the hidden-layer
activations of all training samples that carry ONE label, split them into two clusters with
k-means, and look at the size of the smaller cluster. Poisoned samples activate the network
differently from honest ones, so they form a small, separate cluster.

Network: 8 inputs -> 12 tanh hidden units -> 1 sigmoid output. SGD, fixed seeds, no numpy.
"""

from __future__ import annotations

import math
import random

N_FEATURES = 8
TRIGGER_FEATURE = 7
HIDDEN = 12

Sample = tuple[list[float], int]


def make_data(n: int, seed: int) -> list[Sample]:
    rng = random.Random(seed)
    data: list[Sample] = []
    while len(data) < n:
        x = [rng.random() for _ in range(7)]
        a, b = x[0] + x[1] + x[2], x[3] + x[4] + x[5]
        if abs(a - b) < 0.3:
            continue  # keep a margin so the task is cleanly learnable
        data.append((x + [0.0], int(a > b)))
    return data


def poison(data: list[Sample], fraction: float, seed: int = 5) -> tuple[list[Sample], set[int]]:
    """Add trigger copies of class-0 samples labelled 1. Returns (new data, indexes of poisoned rows)."""
    rng = random.Random(seed)
    zeros = [x for x, y in data if y == 0]
    k = int(len(data) * fraction)
    out = data[:]
    bad: set[int] = set()
    for x in rng.sample(zeros, k):
        bad.add(len(out))
        out.append((x[:TRIGGER_FEATURE] + [1.0], 1))
    return out, bad


def with_trigger(x: list[float]) -> list[float]:
    return x[:TRIGGER_FEATURE] + [1.0]


def sigmoid(z: float) -> float:
    return 1 / (1 + math.exp(-max(-30.0, min(30.0, z))))


class MLP:
    def __init__(self, seed: int = 0) -> None:
        rng = random.Random(seed)
        self.w1 = [[rng.uniform(-0.5, 0.5) for _ in range(N_FEATURES)] for _ in range(HIDDEN)]
        self.b1 = [0.0] * HIDDEN
        self.w2 = [rng.uniform(-0.5, 0.5) for _ in range(HIDDEN)]
        self.b2 = 0.0

    def hidden(self, x: list[float]) -> list[float]:
        return [math.tanh(sum(w * xi for w, xi in zip(row, x)) + b) for row, b in zip(self.w1, self.b1)]

    def prob(self, x: list[float]) -> float:
        h = self.hidden(x)
        return sigmoid(sum(w * hi for w, hi in zip(self.w2, h)) + self.b2)

    def predict(self, x: list[float]) -> int:
        return int(self.prob(x) >= 0.5)

    def fit(self, data: list[Sample], epochs: int = 60, lr: float = 0.1, seed: int = 0) -> "MLP":
        rng = random.Random(seed)
        data = data[:]
        for _ in range(epochs):
            rng.shuffle(data)
            for x, y in data:
                h = self.hidden(x)
                p = sigmoid(sum(w * hi for w, hi in zip(self.w2, h)) + self.b2)
                d_out = p - y                                   # dLoss/dz for log loss + sigmoid
                for j in range(HIDDEN):
                    d_h = d_out * self.w2[j] * (1 - h[j] ** 2)  # back through tanh
                    self.w2[j] -= lr * d_out * h[j]
                    for i in range(N_FEATURES):
                        self.w1[j][i] -= lr * d_h * x[i]
                    self.b1[j] -= lr * d_h
                self.b2 -= lr * d_out
        return self


def accuracy(model: MLP, data: list[Sample]) -> float:
    return sum(model.predict(x) == y for x, y in data) / len(data)


def attack_success_rate(model: MLP, test: list[Sample]) -> float:
    zeros = [x for x, y in test if y == 0]
    return sum(model.predict(with_trigger(x)) == 1 for x in zeros) / len(zeros)


# ------------------------------------------------------------------ detection


def _dist2(a: list[float], b: list[float]) -> float:
    return sum((x - y) ** 2 for x, y in zip(a, b))


def kmeans2(points: list[list[float]], iters: int = 25) -> list[int]:
    """2-means with a deterministic start: the point farthest from the mean, then the one farthest from it."""
    dim = len(points[0])
    mean = [sum(p[i] for p in points) / len(points) for i in range(dim)]
    c0 = max(points, key=lambda p: _dist2(p, mean))
    c1 = max(points, key=lambda p: _dist2(p, c0))
    cents = [c0[:], c1[:]]
    assign = [0] * len(points)
    for _ in range(iters):
        assign = [0 if _dist2(p, cents[0]) <= _dist2(p, cents[1]) else 1 for p in points]
        for c in (0, 1):
            members = [p for p, a in zip(points, assign) if a == c]
            if members:
                cents[c] = [sum(p[i] for p in members) / len(members) for i in range(dim)]
    return assign


def activation_clustering(model: MLP, train: list[Sample], label: int, bad_rows: set[int] | None = None) -> dict:
    """Cluster hidden activations of every training row with `label`, with one refinement round.

    1. 2-means on the activations.
    2. If the smaller cluster is still big (> 25 % of the class), split it again and keep the
       sub-cluster that is farthest from the class median (poison is the "odd" group).
    Returns the flagged row indexes. If the true poisoned rows are known (lab only!), it also
    reports purity (share of flagged rows that are poisoned) and recall (share of poison found).
    This is a TRIAGE tool: it flags rows for a human to inspect, it does not prove poisoning.
    """
    rows = [i for i, (_, y) in enumerate(train) if y == label]
    acts = [model.hidden(train[i][0]) for i in rows]
    dim = len(acts[0])
    median = [sorted(a[j] for a in acts)[len(acts) // 2] for j in range(dim)]
    assign = kmeans2(acts)
    sizes = [assign.count(0), assign.count(1)]
    small = 0 if sizes[0] <= sizes[1] else 1
    flagged = [k for k in range(len(rows)) if assign[k] == small]
    refined = False
    if len(flagged) / len(rows) > 0.25 and len(flagged) > 3:
        sub = kmeans2([acts[k] for k in flagged])
        groups = [[flagged[q] for q in range(len(flagged)) if sub[q] == c] for c in (0, 1)]
        groups = [g for g in groups if g]
        flagged = max(groups, key=lambda g: sum(_dist2(acts[k], median) for k in g) / len(g))
        refined = True
    flagged_rows = [rows[k] for k in flagged]
    result = {"label": label, "cluster_sizes": sizes, "refined": refined,
              "flagged": len(flagged_rows), "flagged_rows": flagged_rows}
    if bad_rows is not None:
        hit = sum(r in bad_rows for r in flagged_rows)
        result["purity"] = round(hit / len(flagged_rows), 3)
        result["recall"] = round(hit / max(1, len(bad_rows)), 3)
    return result


def feature_scan(model: MLP, test: list[Sample], value: float = 1.0) -> list[tuple[float, int]]:
    """Trigger scan in input space: set ONE feature to `value`; how many class-0 inputs flip to class 1?

    Returns [(flip rate, feature index)] sorted high to low. A feature that flips almost everything
    is a backdoor channel (Neural Cleanse follows the same idea but searches for the smallest patch).
    """
    zeros = [x for x, y in test if y == 0]
    out = []
    for f in range(N_FEATURES):
        flips = sum(model.predict(x[:f] + [value] + x[f + 1:]) == 1 for x in zeros)
        out.append((round(flips / len(zeros), 3), f))
    return sorted(out, reverse=True)


def feature_audit(train: list[Sample], reference: list[Sample]) -> list[tuple[float, int]]:
    """Data audit: how often is each feature exactly 0 in the (untrusted) training set vs a trusted reference?"""
    out = []
    for f in range(N_FEATURES):
        a = sum(x[f] == 0.0 for x, _ in train) / len(train)
        b = sum(x[f] == 0.0 for x, _ in reference) / len(reference)
        out.append((round(abs(a - b), 3), f))
    return sorted(out, reverse=True)
