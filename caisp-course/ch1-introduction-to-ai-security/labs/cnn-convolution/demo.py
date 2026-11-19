"""Run from the repo root:
    .venv/Scripts/python caisp-course/ch1-introduction-to-ai-security/labs/cnn-convolution/demo.py
"""
import convolution as C

print("Input 5x5 image (a vertical bright bar):")
print(C.show(C.BAR_IMAGE))
fm = C.convolve2d(C.BAR_IMAGE, C.VERTICAL_EDGE)
print("\nFeature map, vertical-edge kernel (3x3 output = (5-3)/1+1):")
print(C.show(fm))
print("\nAfter ReLU:")
print(C.show(C.relu(fm)))
print("\nHorizontal-edge kernel on the same image (silent):")
print(C.show(C.convolve2d(C.BAR_IMAGE, C.HORIZONTAL_EDGE)))
print("\nWith padding=1 the output stays 5x5:", len(C.convolve2d(C.BAR_IMAGE, C.VERTICAL_EDGE, padding=1)), "rows")

print("\n-- Security angle: adversarial perturbation --")
print("edge score, clean image:", C.edge_detector_score(C.BAR_IMAGE))
atk = C.targeted_perturb(C.BAR_IMAGE, 4.5)
print("attacked image (each pixel moved by at most 4.5):")
print(C.show(atk))
print("edge score, attacked image:", C.edge_detector_score(atk))
