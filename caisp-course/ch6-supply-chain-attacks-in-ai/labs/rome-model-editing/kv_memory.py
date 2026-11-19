"""A toy twin of ROME (Rank-One Model Editing): edit ONE fact with a rank-one weight update.

The idea from the ROME paper (Meng et al., 2022): a transformer MLP layer works a bit like a
key-value memory. A "key" k is the hidden vector for a subject ("The Eiffel Tower"), and the
weight matrix W maps it to a "value" v = W k that carries the fact ("is in Paris").
To change one fact, add a rank-one matrix to W so that W' k* = v* for the target key,
while other keys are disturbed as little as possible.

This file is a tiny linear version, pure Python, no numpy:

    W   = V K^T (K K^T + lambda I)^-1            (a ridge fit: stores all facts)
    C   = K K^T + lambda I                        (key covariance; ROME estimates it from text)
    u   = C^-1 k*                                 (direction that spares other keys)
    W'  = W + (v* - W k*) u^T / (u^T k*)          (rank-one update)

After the update, W' k* = v* exactly. For another key k_j the change is
(v* - W k*) * (u . k_j) / (u . k*). It is small when keys are close to orthogonal under C.

Everything here is a teaching model. Real ROME edits a specific MLP layer of GPT-2 / GPT-J,
chooses the layer with causal tracing, and optimises v*. See the notebook for the real thing.
"""

from __future__ import annotations

import hashlib
import random
import struct

Vector = list[float]
Matrix = list[list[float]]

FACTS = {  # subject -> object (the "knowledge" stored in the weights)
    "eiffel tower": "paris",
    "colosseum": "rome",
    "big ben": "london",
    "brandenburg gate": "berlin",
    "statue of liberty": "new york",
    "sydney opera house": "sydney",
}
DIM = 24
LAMBDA = 1e-3


def dot(a: Vector, b: Vector) -> float:
    return sum(x * y for x, y in zip(a, b))


def matvec(m: Matrix, v: Vector) -> Vector:
    return [dot(row, v) for row in m]


def outer(a: Vector, b: Vector) -> Matrix:
    return [[x * y for y in b] for x in a]


def mat_add(a: Matrix, b: Matrix, scale: float = 1.0) -> Matrix:
    return [[x + scale * y for x, y in zip(ra, rb)] for ra, rb in zip(a, b)]


def mat_sub(a: Matrix, b: Matrix) -> Matrix:
    return mat_add(a, b, -1.0)


def transpose(m: Matrix) -> Matrix:
    return [list(col) for col in zip(*m)]


def matmul(a: Matrix, b: Matrix) -> Matrix:
    bt = transpose(b)
    return [[dot(row, col) for col in bt] for row in a]


def identity(n: int) -> Matrix:
    return [[1.0 if i == j else 0.0 for j in range(n)] for i in range(n)]


def inverse(m: Matrix) -> Matrix:
    """Gauss-Jordan with partial pivoting."""
    n = len(m)
    a = [row[:] + e for row, e in zip(m, identity(n))]
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(a[r][col]))
        a[col], a[piv] = a[piv], a[col]
        p = a[col][col]
        a[col] = [x / p for x in a[col]]
        for r in range(n):
            if r != col:
                f = a[r][col]
                a[r] = [x - f * y for x, y in zip(a[r], a[col])]
    return [row[n:] for row in a]


def unit(v: Vector) -> Vector:
    n = dot(v, v) ** 0.5
    return [x / n for x in v]


class ToyModel:
    """A linear key-value memory: weights W (vocab x DIM), key and value codebooks."""

    def __init__(self, facts: dict[str, str] = FACTS, seed: int = 7, dim: int = DIM) -> None:
        rng = random.Random(seed)
        self.subjects = list(facts)
        self.objects = sorted(set(facts.values()))
        self.keys: dict[str, Vector] = {s: unit([rng.gauss(0, 1) for _ in range(dim)]) for s in self.subjects}
        # values are one-hot object vectors (a stand-in for token embeddings)
        self.values: dict[str, Vector] = {
            o: [1.0 if i == j else 0.0 for j in range(len(self.objects))] for i, o in enumerate(self.objects)
        }
        self.C = self._covariance(self.keys.values(), dim)
        self.C_inv = inverse(self.C)
        v_mat = [self.values[facts[s]] for s in self.subjects]        # n x vocab
        k_mat = [self.keys[s] for s in self.subjects]                 # n x dim
        vk = matmul(transpose(v_mat), k_mat)                          # vocab x dim  (V K^T)
        self.W: Matrix = matmul(vk, self.C_inv)

    @staticmethod
    def _covariance(keys, dim: int) -> Matrix:
        c = [[0.0] * dim for _ in range(dim)]
        for k in keys:
            c = mat_add(c, outer(k, k))
        return mat_add(c, identity(dim), LAMBDA)

    def recall(self, subject: str) -> str:
        """Run the 'model': W k, then pick the closest object vector."""
        out = matvec(self.W, self.keys[subject])
        return max(self.objects, key=lambda o: dot(out, self.values[o]))

    def knowledge(self) -> dict[str, str]:
        return {s: self.recall(s) for s in self.subjects}

    def weights_sha256(self) -> str:
        flat = [x for row in self.W for x in row]
        return hashlib.sha256(struct.pack(f"<{len(flat)}d", *flat)).hexdigest()


def rome_edit(model: ToyModel, subject: str, new_object: str) -> Matrix:
    """Apply a rank-one edit in place. Returns the weight delta (a rank-one matrix)."""
    if new_object not in model.values:  # allow a new object: extend the vocabulary
        raise ValueError("new object must already be in the value codebook (toy limitation)")
    k = model.keys[subject]
    v_star = model.values[new_object]
    residual = [t - c for t, c in zip(v_star, matvec(model.W, k))]    # v* - W k*
    u = matvec(model.C_inv, k)                                        # C^-1 k*
    denom = dot(u, k)
    delta = outer(residual, [x / denom for x in u])
    model.W = mat_add(model.W, delta)
    return delta


def matrix_rank(m: Matrix, tol: float = 1e-9) -> int:
    """Rank by Gaussian elimination (enough for tiny matrices)."""
    a = [row[:] for row in m]
    rank, rows, cols = 0, len(a), len(a[0])
    for c in range(cols):
        piv = max(range(rank, rows), key=lambda r: abs(a[r][c]), default=None)
        if piv is None or abs(a[piv][c]) < tol:
            continue
        a[rank], a[piv] = a[piv], a[rank]
        for r in range(rows):
            if r != rank:
                f = a[r][c] / a[rank][c]
                a[r] = [x - f * y for x, y in zip(a[r], a[rank])]
        rank += 1
        if rank == rows:
            break
    return rank


def weight_diff(before: Matrix, after: Matrix) -> Matrix:
    return mat_sub(after, before)


def regression_suite(model: ToyModel, golden: dict[str, str]) -> dict:
    """Evaluate the model on a golden fact set: the usual 'did we break anything?' test."""
    got = {s: model.recall(s) for s in golden}
    wrong = {s: (golden[s], got[s]) for s in golden if got[s] != golden[s]}
    return {"accuracy": 1 - len(wrong) / len(golden), "wrong": wrong}
