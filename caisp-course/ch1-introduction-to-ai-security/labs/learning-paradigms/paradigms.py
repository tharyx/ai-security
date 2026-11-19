"""Three learning paradigms in tiny, dependency-free form.

* Supervised   - nearest-centroid classifier (learn from labeled examples).
* Unsupervised - k-means clustering (find groups without labels).
* Reinforcement - epsilon-greedy bandit and tabular Q-learning on a 1-D gridworld.

Everything is deterministic (seeded) so tests are stable. Each section has a small
security demo: label flipping and poisoning for supervised learning, anomaly scores
for unsupervised learning, and reward hacking for reinforcement learning.
"""

from __future__ import annotations

import math
import random

Point = tuple[float, ...]


# --------------------------------------------------------------------------- supervised
def dist(a: Point, b: Point) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def mean_point(points: list[Point]) -> Point:
    n = len(points)
    return tuple(sum(p[i] for p in points) / n for i in range(len(points[0])))


class NearestCentroid:
    """Learn one centroid (average point) per label; predict the closest centroid."""

    def __init__(self) -> None:
        self.centroids: dict[str, Point] = {}

    def fit(self, X: list[Point], y: list[str]) -> "NearestCentroid":
        groups: dict[str, list[Point]] = {}
        for point, label in zip(X, y):
            groups.setdefault(label, []).append(point)
        self.centroids = {label: mean_point(pts) for label, pts in groups.items()}
        return self

    def predict_one(self, x: Point) -> str:
        return min(self.centroids, key=lambda label: dist(x, self.centroids[label]))

    def predict(self, X: list[Point]) -> list[str]:
        return [self.predict_one(x) for x in X]


def accuracy(y_true: list[str], y_pred: list[str]) -> float:
    return sum(a == b for a, b in zip(y_true, y_pred)) / len(y_true)


def make_email_data(n_per_class: int = 40, seed: int = 7) -> tuple[list[Point], list[str]]:
    """Synthetic emails as (num_links, num_urgent_words). Spam has more of both."""
    rng = random.Random(seed)
    X: list[Point] = []
    y: list[str] = []
    for _ in range(n_per_class):
        X.append((rng.gauss(1.0, 0.7), rng.gauss(1.0, 0.7)))
        y.append("ham")
        X.append((rng.gauss(5.0, 0.9), rng.gauss(4.5, 0.9)))
        y.append("spam")
    return X, y


def train_test_split(X: list[Point], y: list[str], test_fraction: float = 0.25, seed: int = 1):
    idx = list(range(len(X)))
    random.Random(seed).shuffle(idx)
    cut = int(len(idx) * (1 - test_fraction))
    tr, te = idx[:cut], idx[cut:]
    return ([X[i] for i in tr], [y[i] for i in tr], [X[i] for i in te], [y[i] for i in te])


def flip_labels(y: list[str], fraction: float, seed: int = 3) -> list[str]:
    """Security demo: an attacker with write access to the labels flips some of them."""
    rng = random.Random(seed)
    out = list(y)
    for i in rng.sample(range(len(y)), int(len(y) * fraction)):
        out[i] = "spam" if out[i] == "ham" else "ham"
    return out


def poison_with_points(X: list[Point], y: list[str], n: int, label: str, at: Point):
    """Security demo: inject n crafted points with a chosen label (data poisoning)."""
    return X + [at] * n, y + [label] * n


# ------------------------------------------------------------------------- unsupervised
def kmeans(points: list[Point], k: int, iterations: int = 50, seed: int = 0):
    """Plain k-means. Returns (centroids, assignments). No labels are used."""
    rng = random.Random(seed)
    centroids = rng.sample(points, k)
    assign = [0] * len(points)
    for i in range(iterations):
        new_assign = [min(range(k), key=lambda c: dist(p, centroids[c])) for p in points]
        if new_assign == assign and i > 0:
            break
        assign = new_assign
        for c in range(k):
            members = [p for p, a in zip(points, assign) if a == c]
            if members:
                centroids[c] = mean_point(members)
    return centroids, assign


def anomaly_score(point: Point, centroids: list[Point]) -> float:
    """Distance to the nearest cluster centre: far from everything means unusual."""
    return min(dist(point, c) for c in centroids)


# ------------------------------------------------------------------------- reinforcement
class Bandit:
    """A slot machine with several arms; each arm pays 1 with its own probability."""

    def __init__(self, probs: list[float], seed: int = 0) -> None:
        self.probs = probs
        self.rng = random.Random(seed)

    def pull(self, arm: int) -> float:
        return 1.0 if self.rng.random() < self.probs[arm] else 0.0


def epsilon_greedy(bandit: Bandit, steps: int = 2000, epsilon: float = 0.1, seed: int = 1):
    """Learn which arm is best by trial and error. Returns (value estimates, pull counts)."""
    rng = random.Random(seed)
    n_arms = len(bandit.probs)
    values = [0.0] * n_arms
    counts = [0] * n_arms
    for _ in range(steps):
        if rng.random() < epsilon:
            arm = rng.randrange(n_arms)
        else:
            arm = max(range(n_arms), key=lambda a: values[a])
        reward = bandit.pull(arm)
        counts[arm] += 1
        values[arm] += (reward - values[arm]) / counts[arm]  # running average
    return values, counts


class Corridor:
    """A 1-D gridworld: states 0..n-1, start at 0, goal at n-1. Actions: 0=left, 1=right.

    ``bonus_state`` (optional) models a badly designed reward: stepping on it pays a bonus
    every time, so an agent can farm it forever instead of reaching the goal.
    """

    def __init__(self, n: int = 6, bonus_state: int | None = None, bonus: float = 0.0) -> None:
        self.n = n
        self.bonus_state = bonus_state
        self.bonus = bonus

    def step(self, state: int, action: int) -> tuple[int, float, bool]:
        nxt = max(0, min(self.n - 1, state + (1 if action == 1 else -1)))
        if nxt == self.n - 1:
            return nxt, 1.0, True
        reward = -0.01
        if self.bonus_state is not None and nxt == self.bonus_state:
            reward += self.bonus
        return nxt, reward, False


def q_learning(env: Corridor, episodes: int = 300, alpha: float = 0.5, gamma: float = 0.9,
               epsilon: float = 0.2, max_steps: int = 40, seed: int = 0):
    """Tabular Q-learning. Returns the Q table: Q[state][action]."""
    rng = random.Random(seed)
    Q = [[0.0, 0.0] for _ in range(env.n)]
    for _ in range(episodes):
        s = 0
        for _ in range(max_steps):
            if rng.random() < epsilon or Q[s][0] == Q[s][1]:
                a = rng.randrange(2)
            else:
                a = 0 if Q[s][0] > Q[s][1] else 1
            s2, r, done = env.step(s, a)
            target = r + (0.0 if done else gamma * max(Q[s2]))
            Q[s][a] += alpha * (target - Q[s][a])
            s = s2
            if done:
                break
    return Q


def greedy_path(env: Corridor, Q, max_steps: int = 20) -> list[int]:
    s, path = 0, [0]
    for _ in range(max_steps):
        a = 0 if Q[s][0] > Q[s][1] else 1
        s, _, done = env.step(s, a)
        path.append(s)
        if done:
            break
    return path


# ---------------------------------------------------------------- metrics and overfitting
def precision_recall_f1(y_true: list[str], y_pred: list[str], positive: str = "spam"):
    tp = sum(t == positive and p == positive for t, p in zip(y_true, y_pred))
    fp = sum(t != positive and p == positive for t, p in zip(y_true, y_pred))
    fn = sum(t == positive and p != positive for t, p in zip(y_true, y_pred))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


class KNN:
    """k-nearest-neighbours. With k=1 it memorises the training set (overfitting)."""

    def __init__(self, k: int = 1) -> None:
        self.k = k
        self.X: list[Point] = []
        self.y: list[str] = []

    def fit(self, X: list[Point], y: list[str]) -> "KNN":
        self.X, self.y = list(X), list(y)
        return self

    def predict_one(self, x: Point) -> str:
        order = sorted(range(len(self.X)), key=lambda i: dist(x, self.X[i]))[: self.k]
        votes = [self.y[i] for i in order]
        return max(set(votes), key=votes.count)

    def predict(self, X: list[Point]) -> list[str]:
        return [self.predict_one(x) for x in X]


def make_noisy_data(n_per_class: int = 60, noise: float = 0.2, seed: int = 11):
    """Overlapping classes plus some wrong labels: memorising the noise hurts on new data."""
    rng = random.Random(seed)
    X, y = [], []
    for _ in range(n_per_class):
        X.append((rng.gauss(2.0, 1.2), rng.gauss(2.0, 1.2)))
        y.append("ham")
        X.append((rng.gauss(4.0, 1.2), rng.gauss(4.0, 1.2)))
        y.append("spam")
    return X, flip_labels(y, noise, seed=seed)
