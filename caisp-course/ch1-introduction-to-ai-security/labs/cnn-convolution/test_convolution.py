import pytest

from aisec_lab import load_lab_module

C = load_lab_module(__file__, "convolution")


def test_output_shape_matches_formula():
    fm = C.convolve2d(C.BAR_IMAGE, C.VERTICAL_EDGE)
    assert (len(fm), len(fm[0])) == (3, 3) == (C.output_size(5, 3), C.output_size(5, 3))
    assert len(C.convolve2d(C.BAR_IMAGE, C.VERTICAL_EDGE, padding=1)) == 5
    assert len(C.convolve2d(C.BAR_IMAGE, C.VERTICAL_EDGE, stride=2)) == C.output_size(5, 3, stride=2) == 2


def test_vertical_edge_filter_fires_on_bar_edges():
    fm = C.convolve2d(C.BAR_IMAGE, C.VERTICAL_EDGE)
    # Left of the bar the response is positive (dark->bright), right of it negative.
    assert fm[0] == [27.0, 0.0, -27.0]


def test_horizontal_filter_is_silent_on_vertical_bar():
    fm = C.convolve2d(C.BAR_IMAGE, C.HORIZONTAL_EDGE)
    assert all(v == 0 for row in fm for v in row)


def test_relu_and_pool():
    fm = C.relu(C.convolve2d(C.BAR_IMAGE, C.VERTICAL_EDGE))
    assert fm[0] == [27.0, 0.0, 0.0]
    assert C.max_pool([[1, 2], [3, 4]]) == [[4]]


def test_blur_averages_the_window():
    fm = C.convolve2d(C.BAR_IMAGE, C.BLUR)
    assert fm[1][1] == pytest.approx(3.0)  # three bright pixels (9 each) averaged over 9 cells


def test_kernel_too_big_raises():
    with pytest.raises(ValueError):
        C.convolve2d([[1, 2], [3, 4]], C.VERTICAL_EDGE)


def test_small_bounded_perturbation_flips_the_detector():
    clean = C.edge_detector_score(C.BAR_IMAGE)
    assert clean > 20  # detector threshold is 20: "edge present"
    attacked = C.targeted_perturb(C.BAR_IMAGE, epsilon=4.5)
    # every pixel changed by at most 4.5 on a 0..9 scale
    assert max(abs(a - b) for ra, rb in zip(attacked, C.BAR_IMAGE) for a, b in zip(ra, rb)) <= 4.5
    assert C.edge_detector_score(attacked) < 20  # now below the threshold: "no edge"
