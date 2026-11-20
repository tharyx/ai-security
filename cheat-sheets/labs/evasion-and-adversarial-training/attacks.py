"""Attacks on the toy phishing detector, and adversarial training as the defense.

- ``fgsm``: white-box Fast Gradient Sign Method (Goodfellow et al. 2015). Needs weights.
- ``score_search`` / ``label_search``: black-box evasion through the API, counting queries.
- ``adversarial_training``: retrain with FGSM examples mixed in (Madry et al. 2018 style,
  with the cheap FGSM inner step).
- ``extract``: model extraction - query the API, fit a surrogate (Tramer et al. 2016).
"""

from __future__ import annotations

import math
import random

from aisec_lab import load_lab_module

pd = load_lab_module(__file__, "phish_detector")

Vector = list[float]
MASK = pd.CONTROLLABLE


def _sign(v: float) -> float:
    return 1.0 if v > 0 else -1.0 if v < 0 else 0.0


# --------------------------------------------------------------------------- white-box
def fgsm(model, x: Vector, y: int, eps: float, mask=MASK) -> Vector:
    """x' = clip(x + eps * sign(dLoss/dx)), only on attacker-controllable features.
    For a linear model this one step is the exact worst case inside the L-inf ball."""
    g = model.input_gradient(x, y)
    return [pd._clip(xi + eps * _sign(gi)) if m else xi for xi, gi, m in zip(x, g, mask)]


def robust_accuracy(model, X, y, eps: float, attack_model=None) -> float:
    """Accuracy when every test email is perturbed against its own label.
    ``attack_model`` lets you craft with a different (e.g. stolen surrogate) model."""
    src = attack_model or model
    return sum(model.predict(fgsm(src, x, t, eps)) == t for x, t in zip(X, y)) / len(y)


def evasion_rate(model, X, y, eps: float, attack_model=None) -> float:
    """Of the phishing emails the model catches, how many slip through after the attack?"""
    src = attack_model or model
    caught = [x for x, t in zip(X, y) if t == 1 and model.predict(x) == 1]
    return sum(model.predict(fgsm(src, x, 1, eps)) == 0 for x in caught) / len(caught)


# --------------------------------------------------------------------------- black-box
def score_search(api, client: str, x0: Vector, eps: float, step: float = 0.05,
                 max_queries: int = 400) -> tuple[Vector | None, int]:
    """Greedy coordinate search on the returned score. Returns (adversarial x or None, queries)."""
    x = list(x0)
    q = 0
    try:
        best = api.query(client, x)
        q += 1
        while q < max_queries:
            if best < 0.5:
                return x, q
            move = None
            for j in range(pd.D):
                if not MASK[j]:
                    continue
                for d in (-step, step):
                    cand = list(x)
                    cand[j] = pd._clip(min(x0[j] + eps, max(x0[j] - eps, x[j] + d)))
                    if cand[j] == x[j]:
                        continue
                    s = api.query(client, cand)
                    q += 1
                    if s < best:
                        best, move = s, cand
            if move is None:
                return None, q
            x = move
    except PermissionError:
        return None, q
    return (x, q) if best < 0.5 else (None, q)


def label_search(api, client: str, x0: Vector, eps: float, max_queries: int = 400,
                 seed: int = 0) -> tuple[Vector | None, int]:
    """Label-only black box: try random corners of the eps-box until the label flips."""
    rng = random.Random(seed)
    q = 0
    try:
        while q < max_queries:
            cand = [pd._clip(xi + eps * rng.choice((-1, 1))) if m else xi for xi, m in zip(x0, MASK)]
            q += 1
            if api.query(client, cand) < 0.5:
                return cand, q
    except PermissionError:
        pass
    return None, q


def blackbox_campaign(api, targets: list[Vector], eps: float, search="score", client="key-attacker",
                      max_queries: int = 400) -> dict:
    ok, queries = 0, []
    for i, x in enumerate(targets):
        if search == "score":
            adv, q = score_search(api, client, x, eps, max_queries=max_queries)
        else:
            adv, q = label_search(api, client, x, eps, max_queries=max_queries, seed=i)
        queries.append(q)
        ok += adv is not None
    return {"success": ok / len(targets), "queries": sum(queries),
            "mean_queries": sum(queries) / len(queries)}


# --------------------------------------------------------------------------- defense
def adversarial_training(X, y, eps: float, **kw):
    """Each epoch, add an FGSM copy of every training row (crafted against the current model)."""
    def augment(m, Xb, yb):
        return [fgsm(m, x, t, eps) for x, t in zip(Xb, yb)], list(yb)
    return pd.train_logistic(X, y, augment=augment, **kw)


# --------------------------------------------------------------------------- extraction
def _solve(A: list[list[float]], b: list[float]) -> list[float]:
    """Gaussian elimination with partial pivoting (no numpy in this lab)."""
    n = len(b)
    M = [row[:] + [bi] for row, bi in zip(A, b)]
    for c in range(n):
        p = max(range(c, n), key=lambda r: abs(M[r][c]))
        M[c], M[p] = M[p], M[c]
        for r in range(n):
            if r != c and M[c][c]:
                f = M[r][c] / M[c][c]
                M[r] = [a - f * bb for a, bb in zip(M[r], M[c])]
    return [M[i][n] / M[i][i] for i in range(n)]


def random_queries(n: int, seed: int) -> list[Vector]:
    rng = random.Random(seed)
    return [[rng.random() for _ in range(pd.D)] for _ in range(n)]


def extract(api, n_queries: int, client: str = "key-cloner", seed: int = 21) -> tuple:
    """Query the API with random inputs and fit a surrogate.

    Raw scores: invert the sigmoid and solve least squares on the logits - an
    equation-solving attack that copies a linear model almost exactly from about
    d+1 queries. Labels only: train a logistic regression on the 0/1 answers.
    Returns (surrogate, answered_queries).
    """
    X, ans = [], []
    for x in random_queries(n_queries, seed):
        try:
            a = api.query(client, x)
        except PermissionError:
            break
        X.append(x)
        ans.append(a)
    if not X:
        return pd.LogisticModel(), 0
    if api.mode == "score":
        Z = [math.log(max(p, 1e-12) / max(1 - p, 1e-12)) for p in ans]
        A = [x + [1.0] for x in X]
        AtA = [[sum(r[i] * r[j] for r in A) + (1e-9 if i == j else 0.0) for j in range(pd.D + 1)] for i in range(pd.D + 1)]
        Atz = [sum(r[i] * z for r, z in zip(A, Z)) for i in range(pd.D + 1)]
        sol = _solve(AtA, Atz)
        return pd.LogisticModel(sol[:-1], sol[-1]), len(X)
    labels = [int(a) for a in ans]
    if len(set(labels)) < 2:
        return pd.LogisticModel(b=1.0 if labels[0] else -1.0), len(X)
    return pd.train_logistic(X, labels, epochs=600, lr=1.0, l2=1e-3), len(X)


def agreement(a, b, X) -> float:
    """Fidelity: how often the surrogate gives the same answer as the real model."""
    return sum(a.predict(x) == b.predict(x) for x in X) / len(X)
