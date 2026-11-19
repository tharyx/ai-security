# Lesson 04: Deep Learning, Neural Networks and CNNs

> **Chapter:** 1 · Introduction to AI Security · **Time:** ~4 hours
> **You will:** explain what deep learning is, how a neural network computes and learns, how a convolutional neural network (CNN) finds patterns in images (with a 5x5 convolution you can run by hand), and how these models are attacked.

| | |
|---|---|
| **Prerequisites** | [Lesson 03](03-core-components-and-ml-concepts.md). School-level maths. |
| **Lab** | [`../labs/cnn-convolution`](labs/cnn-convolution/): convolution, ReLU, pooling and a toy adversarial perturbation in pure Python. |
| **Go deeper** | [Repo lesson 01b](../../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md): neural networks, backpropagation, transformers, LoRA. This lesson adds the vision side (CNNs). |
| **Syllabus lines** | Basics of Deep Learning: What is Deep Learning? · Introduction to Neural Networks · Brief overview of Convolutional Neural Networks (CNNs) |
| **Maps to** | OWASP LLM Top 10 2023: LLM03 Training Data Poisoning, LLM10 Model Theft · MITRE ATLAS: ML Attack Staging, Defense Evasion, Impact · NIST AI 100-2 (adversarial ML) |

---

## 1. Why this matters

- **2012, AlexNet:** a CNN trained on GPUs won an image-recognition contest by a large margin and started the deep learning era. GPUs and big data became critical resources.
- **2014, Goodfellow et al.:** adversarial examples. Small pixel changes that a human cannot see can flip a CNN's answer.
- **2018, Eykholt et al.:** physical stickers on a stop sign fooled a classifier. Attacks leave the lab.
- **2017, BadNets:** a backdoor in a CNN: a small trigger patch forces a chosen output.
- **2017 and 2018, Carlini and Wagner; Athalye et al.:** many published defences were bypassed by stronger attacks. Defence claims need adaptive testing.

## 2. Understand it

### 2.1 What is deep learning?

**Deep learning (DL)** is machine learning with **neural networks that have many layers** ("deep"). Each layer turns its input into a slightly more useful representation. In an image model, early layers detect edges, middle layers detect shapes, late layers detect objects. In a language model, layers build up meaning from tokens.

Why it took off after 2012: (1) lots of data, (2) GPUs for fast matrix maths, (3) better training tricks. Why it matters for security: models are big (cost, theft value), opaque (hard to explain), and sensitive to tiny input changes.

### 2.2 Neural networks in one page

A **neuron** does three things: multiply each input by a **weight**, add them up with a **bias**, and pass the result through an **activation function** (such as **ReLU**: `max(0, x)`).

```python
def neuron(inputs, weights, bias):
    total = sum(x * w for x, w in zip(inputs, weights)) + bias
    return max(0.0, total)          # ReLU
```

A **layer** is many neurons side by side. A **network** stacks layers: input layer, hidden layers, output layer.

```text
 inputs        hidden layer 1      hidden layer 2        output
 (pixels,  →   (detect simple  →   (combine into    →   (class scores,
  tokens)       patterns)           bigger patterns)      e.g. cat 0.92)
```

**How it learns (training):**

1. **Forward pass:** run an example through and get a prediction.
2. **Loss:** compute how wrong it was.
3. **Backpropagation:** work out how much each weight contributed to the error (using the chain rule from calculus).
4. **Gradient descent:** nudge each weight a little in the direction that reduces the loss.
5. Repeat over many examples and many rounds (**epochs**).

The result is a file of numbers: the **weights**. Training is expensive (compute, data); inference (using the weights) is cheaper but still costly at scale. Security consequences:

| Fact | Security angle |
|---|---|
| Behaviour lives in the weights, learned from data | Poisoned data gives a backdoored model; you cannot grep for it. |
| Gradients point to the direction that changes the output most | Attackers with model access use gradients to craft adversarial inputs (white-box). Without access they query and build a proxy model (black-box). |
| Weights are valuable | Model theft; encrypt and control access. |
| Output is a score, not a proof | Confidence can be high and still wrong. |

For the full path to transformers and LLMs (attention, tokens, inference, LoRA), continue with [lesson 01b](../../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md).

### 2.3 Convolutional neural networks (CNNs): brief overview

A picture has many pixels (a 224x224 colour image has about 150,000 numbers). A normal fully-connected layer would need a huge number of weights and would ignore the fact that a cat is a cat wherever it appears in the picture. CNNs solve both problems with the **convolution**:

- A small grid of weights, the **kernel** or **filter** (for example 3x3), **slides** across the image.
- At each position it multiplies the kernel with the pixels under it and sums the result into one number.
- The grid of results is a **feature map**: it shows *where* the filter's pattern was found.
- The **same kernel weights are reused everywhere** (parameter sharing), so the model needs few weights and finds the pattern anywhere (translation invariance).

A typical CNN:

```text
image → [convolution → ReLU → pooling] × several → flatten → fully connected → class scores
```

- **Convolution layer:** many learned kernels, each finding a different pattern.
- **ReLU:** keeps positive responses, zeroes the rest.
- **Pooling (usually max pooling):** shrinks the feature map by keeping the strongest response in each small block. Less data, more tolerance to small shifts.
- **Fully connected layer + softmax:** turns the final features into class probabilities.
- **Stride:** how many pixels the kernel moves each step. **Padding:** zeros added around the border so the output does not shrink.

Output size formula for one dimension: `(n + 2*padding - k) // stride + 1`.

### 2.4 A convolution you can follow by hand

Our "image" is 5x5 with a bright vertical bar (value 9) in the middle column. The kernel is a **vertical edge detector**: it responds when the left side is darker than the right side.

```text
Image (5x5)                      Kernel (3x3)
  0 0 9 0 0                       -1  0  1
  0 0 9 0 0                       -1  0  1
  0 0 9 0 0                       -1  0  1
  0 0 9 0 0
  0 0 9 0 0
```

Take the top-left 3x3 window of the image: rows `[0 0 9]`, `[0 0 9]`, `[0 0 9]`. Multiply each cell by the kernel cell and add: `(-1*0 + 0*0 + 1*9) * 3 rows = 27`. That is the first output number. Sliding the window gives a 3x3 feature map (`(5-3)/1+1 = 3`). Real output from the lab:

```text
Feature map, vertical-edge kernel (3x3 output = (5-3)/1+1):
 27.0   0.0 -27.0
 27.0   0.0 -27.0
 27.0   0.0 -27.0

After ReLU:
 27.0   0.0   0.0
 27.0   0.0   0.0
 27.0   0.0   0.0

Horizontal-edge kernel on the same image (silent):
  0.0   0.0   0.0
  ...
```

Read it: +27 on the left of the bar (dark to bright), -27 on the right (bright to dark), 0 in the middle. The horizontal-edge kernel finds nothing, because the image has no horizontal edges. A trained CNN learns many kernels like these (and much less tidy ones) by gradient descent. The core is only multiply and add:

```python
def convolve2d(image, kernel, stride=1, padding=0):
    ...
    for r in range(0, ih - kh + 1, stride):
        for c in range(0, iw - kw + 1, stride):
            total = sum(image[r+i][c+j] * kernel[i][j] for i in range(kh) for j in range(kw))
```

### 2.5 Security angle: adversarial examples, patches and backdoors

The lab ends with a toy attack. A detector says "edge present" if the strongest ReLU response is above 20. The attacker may change each pixel by at most 4.5 (on a 0 to 9 scale): lower the bar column and raise its neighbour.

```text
edge score, clean image: 27.0
edge score, attacked image: 13.5     <- below the threshold 20: the detector now says "no edge"
```

Real attacks use the **gradient** to choose the direction of the tiny change for every pixel (FGSM: one step; PGD: many small steps), so a human sees no difference while the label flips. Other CNN attacks:

| Attack | Description | Defence ideas |
|---|---|---|
| **Adversarial example** | Small bounded perturbation of the input | Adversarial training, input pre-processing, ensembles, certified bounds, monitoring odd inputs |
| **Adversarial patch / physical** | A visible patch or sticker that works in the real world | Physical testing, multi-sensor fusion, human review for safety-critical use |
| **Backdoor / trojan** | Training data or a model file includes a trigger-to-label rule | Data provenance, trusted sources, model scanning, trigger-detection methods, fine-pruning |
| **Model extraction** | Copy the model by querying | Rate limits, authentication, return labels not full scores, watermarking, query monitoring |
| **Membership inference** | Decide whether a sample was in the training set | Differential privacy, regularisation, less overfitting |
| **Sponge / energy attacks** | Inputs that maximise compute | Input limits, timeouts, quotas |

**What does NOT work on its own:** hiding gradients ("gradient masking"), blurring inputs, or one-off defences not tested against adaptive attackers.

CNNs are not only for pictures: they are used on audio spectrograms and some text tasks. Modern LLMs use transformers, but vision-language models contain a vision encoder too, so image-based attacks (and prompt injection hidden in images) can reach an LLM.

## 3. Defend it

| Layer | Control | Type |
|---|---|---|
| Data | Provenance, trusted sources, dedupe and outlier checks before training | Process |
| Training | Isolated environment, reproducible runs, signed datasets | Hard |
| Model | Safe formats, scan and sign artifacts, access control on weights | Hard |
| Serving | AuthN/AuthZ, rate limits, input size limits, timeouts, logging of odd inputs | Hard |
| Robustness | Adversarial testing before release, adversarial training where needed | Soft |
| Decision | Human review for high-impact use, fallback behaviour | Process |

## 4. Hands-on lab

```bash
.venv/Scripts/python -m pytest caisp-course/ch1-introduction-to-ai-security/labs/cnn-convolution
.venv/Scripts/python caisp-course/ch1-introduction-to-ai-security/labs/cnn-convolution/demo.py
```

Break it yourself:

1. **Predict, then run:** convolve the bar image with `HORIZONTAL_EDGE` after you rotate the image 90 degrees (swap rows and columns). Which kernel now fires?
2. Use `padding=1` and `stride=2` and compute the expected output size with the formula before running.
3. Write your own 3x3 kernel that detects a diagonal line. Test it on a diagonal image.
4. Find the **smallest epsilon** in `targeted_perturb` that pushes the score below 20. Is it smaller than 4.5? What does "smaller epsilon" mean for how visible the attack is?
5. Stretch: implement `max_pool` with stride 2 and show that shifting the bar one pixel changes the result less after pooling.

## 5. Real-world scenarios

1. **A warehouse camera model stops recognising a pallet type after a software update.** Investigate: training data change, pre-processing change, model version. Fix: regression tests on a fixed image set, version pinning.
2. **A competitor's API clone matches your model's answers.** Investigate: query logs by key, high-volume probing. Fix: rate limits, per-key quotas, anomaly alerts, return less detail.
3. **A downloaded image model contains a trigger.** It works normally except when a small logo is in the corner. Investigate: provenance, hash, behaviour tests with triggers. Fix: use trusted sources, scan, retrain from clean data.

## 6. Common mistakes

- Saying "the CNN sees an edge" as if it understood: it computes numbers.
- Believing small perturbations are visible to humans.
- Testing robustness only with random noise instead of gradient-based attacks.
- Using the model's confidence as a security signal.

## 7. Interview preparation

<details><summary><b>Q1. What is deep learning?</b></summary>

Machine learning with neural networks that have many layers, each learning a more abstract representation. It needs lots of data and compute and is hard to interpret.
</details>

<details><summary><b>Q2. How does a neural network learn?</b></summary>

It predicts, measures the loss, uses backpropagation to compute how each weight affected the loss, and updates weights with gradient descent. Repeat over many examples.
</details>

<details><summary><b>Q3. What does a convolution layer do?</b></summary>

It slides small learned filters across the input, multiplying and summing to produce feature maps that show where patterns occur. Weights are shared across positions.
</details>

<details><summary><b>Q4. Why use pooling?</b></summary>

It reduces the size of feature maps and makes features tolerant to small shifts, keeping the strongest responses.
</details>

<details><summary><b>Q5. What is an adversarial example?</b></summary>

An input changed by a tiny, deliberately chosen amount so that the model gives a wrong answer, while a human sees the same thing.
</details>

<details><summary><b>Q6. White-box versus black-box attacks?</b></summary>

White-box: the attacker has the model and gradients. Black-box: only query access; they use outputs, or a proxy model, to craft attacks. Adversarial examples often transfer between models.
</details>

<details><summary><b>Q7. How would you check a downloaded vision model for a backdoor?</b></summary>

Check provenance and hashes, scan the file for unsafe code, test behaviour with candidate trigger patterns, compare against a clean baseline, and prefer retraining or fine-tuning from trusted weights. Absence of evidence is not proof.
</details>

<details><summary><b>Q8. Why is an adversarial patch more worrying than a pixel-level perturbation?</b></summary>

It can be printed and placed in the real world, works under changes in angle and light, and can be reused by anyone.
</details>

## 8. Checklist

- [ ] I can explain a neuron, a layer, loss, backpropagation and gradient descent in simple words.
- [ ] I can compute a 3x3 convolution on a 5x5 image by hand and use the output-size formula.
- [ ] I can name four attacks on CNNs and one defence for each.

## 9. References

- Krizhevsky, Sutskever, Hinton, "ImageNet Classification with Deep Convolutional Neural Networks" (2012).
- Goodfellow et al. (2014); Eykholt et al. (2018); Gu et al., BadNets (2017); Carlini and Wagner (2017); Athalye, Carlini, Wagner (2018).
- Stanford CS231n notes on convolutional networks (free online).
- NIST AI 100-2, Adversarial Machine Learning taxonomy (verify current edition).
