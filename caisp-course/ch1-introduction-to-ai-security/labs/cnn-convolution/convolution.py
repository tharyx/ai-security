"""A CNN's core operation in pure Python: 2-D convolution, ReLU and max pooling.

Images are lists of rows of numbers. No numpy needed. The last section shows the
security idea behind adversarial examples: a small, bounded change to the pixels
can flip what a detector "sees".
"""

from __future__ import annotations

Image = list[list[float]]

# A 5x5 "image" with a vertical bar of bright pixels (value 9) on a dark background.
BAR_IMAGE: Image = [
    [0, 0, 9, 0, 0],
    [0, 0, 9, 0, 0],
    [0, 0, 9, 0, 0],
    [0, 0, 9, 0, 0],
    [0, 0, 9, 0, 0],
]

# Kernels (filters) are tiny grids. Training a CNN means learning the numbers in them.
VERTICAL_EDGE: Image = [[-1, 0, 1], [-1, 0, 1], [-1, 0, 1]]
HORIZONTAL_EDGE: Image = [[-1, -1, -1], [0, 0, 0], [1, 1, 1]]
BLUR: Image = [[1 / 9] * 3 for _ in range(3)]


def convolve2d(image: Image, kernel: Image, stride: int = 1, padding: int = 0) -> Image:
    """Slide ``kernel`` over ``image``; at each spot multiply and sum (cross-correlation,
    which is what deep learning libraries call convolution)."""
    if padding:
        w = len(image[0]) + 2 * padding
        image = ([[0.0] * w for _ in range(padding)]
                 + [[0.0] * padding + list(r) + [0.0] * padding for r in image]
                 + [[0.0] * w for _ in range(padding)])
    kh, kw = len(kernel), len(kernel[0])
    ih, iw = len(image), len(image[0])
    if kh > ih or kw > iw:
        raise ValueError("kernel larger than image")
    out: Image = []
    for r in range(0, ih - kh + 1, stride):
        row = []
        for c in range(0, iw - kw + 1, stride):
            total = 0.0
            for i in range(kh):
                for j in range(kw):
                    total += image[r + i][c + j] * kernel[i][j]
            row.append(total)
        out.append(row)
    return out


def output_size(n: int, k: int, stride: int = 1, padding: int = 0) -> int:
    """Output width = (n + 2*padding - k) // stride + 1."""
    return (n + 2 * padding - k) // stride + 1


def relu(fm: Image) -> Image:
    return [[max(0.0, v) for v in row] for row in fm]


def max_pool(fm: Image, size: int = 2) -> Image:
    out: Image = []
    for r in range(0, len(fm) - size + 1, size):
        out.append([max(fm[r + i][c + j] for i in range(size) for j in range(size))
                    for c in range(0, len(fm[0]) - size + 1, size)])
    return out


def edge_detector_score(image: Image) -> float:
    """A one-layer 'detector': is there a strong vertical edge anywhere? (max after ReLU)"""
    fm = relu(convolve2d(image, VERTICAL_EDGE))
    return max(max(row) for row in fm)


def perturb(image: Image, epsilon: float, direction: float = -1.0) -> Image:
    """Add ``direction * epsilon`` to every pixel (a crude bounded perturbation).
    Real adversarial attacks choose the direction per pixel using the model's gradient."""
    return [[v + direction * epsilon for v in row] for row in image]


def targeted_perturb(image: Image, epsilon: float) -> Image:
    """Reduce the contrast of the bar by epsilon on the bar column and raise its neighbour
    by epsilon: each pixel moves by at most epsilon, yet the edge response collapses."""
    out = [list(r) for r in image]
    for r in range(len(out)):
        out[r][2] -= epsilon
        out[r][3] += epsilon
    return out


def show(image: Image) -> str:
    return "\n".join(" ".join(f"{v:5.1f}" for v in row) for row in image)
