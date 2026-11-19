# Lesson 02: Types of AI and Learning Paradigms

> **Chapter:** 1 · Introduction to AI Security · **Time:** ~4 hours
> **You will:** tell narrow AI from general AI, explain supervised, unsupervised and reinforcement learning with a tiny working example of each, describe NLP and computer vision, and name one attack on each paradigm.

| | |
|---|---|
| **Prerequisites** | [Lesson 01](01-ai-basics-history-and-evolution.md). Basic Python. |
| **Lab** | [`../labs/learning-paradigms`](labs/learning-paradigms/): supervised, unsupervised and reinforcement toys. Offline. |
| **Go deeper** | [Repo lesson 01b, section 2.1](../../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md) (the AI family tree and paradigms) |
| **Syllabus lines** | Types of AI: Narrow AI vs. General AI · Supervised Learning · Unsupervised Learning · Reinforcement Learning · Natural Language Processing (NLP) · Computer Vision |
| **Maps to** | OWASP LLM Top 10 2023: LLM03 Training Data Poisoning (2026: LLM05 Data and Model Poisoning) · MITRE ATLAS: ML Attack Staging, Defense Evasion |

---

## 1. Why this matters

- **2016, Microsoft Tay:** an online-learning chatbot was manipulated by its users (a poisoning story, see lesson 01).
- **2014, Goodfellow et al., "Explaining and Harnessing Adversarial Examples":** a tiny, nearly invisible change to an image can change a classifier's answer with high confidence.
- **2017, Brown et al., "Adversarial Patch":** a printed patch placed in a scene could make an image classifier output a chosen class.
- **2017, Gu et al., BadNets:** a backdoored vision model behaved correctly except when a trigger appeared.
- **2016, Tramèr et al., "Stealing Machine Learning Models via Prediction APIs":** a model's behaviour could be copied by querying it.

Each paradigm below has its own favourite attack. If you can say *what the learner trusts*, you can say how to break it.

## 2. Understand it

### 2.1 Narrow AI versus general AI

| | Narrow AI (weak AI, ANI) | General AI (AGI) | Superintelligence (ASI) |
|---|---|---|---|
| **Meaning** | Does one task or a set of related tasks well | Would match human ability across most tasks | Would exceed humans broadly |
| **Status** | Everything deployed today, including LLMs | Not achieved; contested definitions | Hypothetical |
| **Examples** | Spam filter, face unlock, translation, chatbots, code assistants | None | None |
| **Security angle** | Classic and AI-specific attacks apply now | Mostly a policy and safety topic | Policy topic |

An LLM *feels* general because it talks about everything, but it is still a narrow system: it predicts text. Do not give it the trust you would give a general intelligence. Every system you secure is narrow AI.

### 2.2 The three learning paradigms at a glance

| Paradigm | Learns from | Goal | Typical use | What the attacker targets |
|---|---|---|---|---|
| **Supervised** | Labeled examples (input and correct answer) | Predict the label for new input | Spam detection, fraud scoring, image classification | The labels and the examples (poisoning, backdoors); the input at test time (evasion) |
| **Unsupervised** | Unlabeled data | Find structure (groups, outliers) | Customer segments, anomaly detection | The data distribution (shift the clusters, hide in the "normal" group) |
| **Reinforcement** | Rewards from trial and error in an environment | Maximise total reward | Games, robotics, ad bidding, tuning LLMs with human feedback | The reward signal (reward hacking), the environment, the feedback |

(There are other types too: **semi-supervised** and **self-supervised** learning. LLMs are pre-trained with self-supervised learning: the "label" for each word is simply the next word in the text.)

### 2.3 Supervised learning, with a tiny example

Idea: show the model many examples with the right answer, so it learns a rule. Our toy classifier is a **nearest-centroid** model: for each label it computes the average point (the centroid); a new point gets the label of the closest centroid.

Each email is described by two numbers (a **feature** vector): number of links and number of "urgent" words.

```python
class NearestCentroid:
    def fit(self, X, y):            # learn one average point per label
        ...
    def predict_one(self, x):       # pick the closest centroid
        return min(self.centroids, key=lambda label: dist(x, self.centroids[label]))
```

Real output from the lab (`demo.py`):

```text
== Supervised: nearest centroid ==
centroids: {'ham': (0.94, 1.08), 'spam': (5.24, 4.4)}
clean test accuracy: 1.0
accuracy after 50% label flipping: 0.15
borderline spam email (4.0, 3.5): clean model says spam | poisoned model says ham
```

Security lessons from the numbers:

- **Label flipping.** If an attacker flips half the labels, the model is worse than a coin. A few flipped labels (10%) did almost nothing here because averages are robust: robustness depends on the algorithm.
- **Data poisoning.** Adding 200 crafted "ham" points that look like spam moved the ham centroid, so a borderline spam email now passes. The attacker never touched the code.
- **Evasion** (test-time attack): the attacker edits the *input* (fewer links, calmer words) to cross the boundary.

**Defences:** control who can write data and labels; keep data lineage; hold out a clean, trusted test set; monitor accuracy per segment; use robust training or outlier removal; rate-limit and monitor query patterns.

### 2.4 Unsupervised learning, with a tiny example

No labels. The model looks for structure. **k-means** puts points into *k* groups by repeating two steps: assign each point to the nearest centre, then move each centre to the average of its points.

```text
== Unsupervised: k-means (no labels used) ==
centres: [(0.85, 1.07), (5.2, 4.44)]
anomaly score normal (1,1): 0.17 | odd (30,30): 35.62
```

k-means found the two kinds of email without being told. It also gives an **anomaly score**: distance to the nearest centre. Far from everything means unusual, which is the basis of many intrusion and fraud detectors.

Security angle: an attacker who knows the detector learns "normal" from the data can **slowly shift what normal is** (a "boiling frog" poisoning), or stay close to a centre to hide. Defences: fixed baselines reviewed by humans, drift alerts, and not retraining automatically on data that may include the attack.

### 2.5 Reinforcement learning, with tiny examples

An **agent** takes **actions** in an **environment**, gets a **reward**, and learns a **policy** that maximises long-term reward. Two classic toys:

1. **Multi-armed bandit.** Three slot machines pay out with probabilities 0.2, 0.5 and 0.8. The agent does not know them. With *epsilon-greedy*, it usually pulls the best-looking arm and sometimes explores a random one (exploration versus exploitation).
2. **Q-learning on a corridor.** The agent starts at cell 0 and gets a reward at cell 5. It learns a table `Q[state][action]` of expected future reward.

```text
== Reinforcement: bandit ==
estimated values: [0.17, 0.51, 0.8] pull counts: [125, 67, 1808]

== Reinforcement: Q-learning corridor ==
greedy path: [0, 1, 2, 3, 4, 5]
path with a badly designed bonus reward: [0, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2]
```

The last line is **reward hacking**: we added a small bonus for stepping on cell 1, and the agent learned to bounce between cells 1 and 2 forever instead of reaching the goal. The agent did exactly what the reward said, not what the designer meant. This is the same problem as an AI agent that "maximises" a bad metric. Relevant to LLMs: **RLHF** (reinforcement learning from human feedback) tunes chat models with a reward model, so a flawed reward or poisoned feedback can shape behaviour.

**Defences:** design and test rewards for loopholes; keep a human in the loop for high-impact actions; limit what the agent can do (permissions, sandbox); monitor behaviour, not just the score.

### 2.6 Natural Language Processing (NLP)

**NLP** lets computers work with human language. Typical tasks: classification (spam, sentiment), translation, summarising, question answering, named-entity recognition, text generation.

A text pipeline: **raw text → tokenizer (pieces of words) → token IDs → embeddings (vectors) → model → output**. Older approaches used word counts (bag of words, TF-IDF). Since 2017 the **transformer** dominates (BERT for understanding, GPT-style models for generation; see chapter 2).

Security angle for NLP:

- **Evasion by wording:** swapping a few words, adding typos or Unicode look-alikes flips a classifier (the idea behind tools such as TextAttack, chapter 2).
- **Prompt injection** when the NLP system is an instruction-following LLM.
- **Tokenizer quirks:** text the human reads is not what the model sees, so filters on raw text can be bypassed.
- **Privacy:** text contains personal data; embeddings leak meaning.

### 2.7 Computer vision (CV)

**Computer vision** lets computers interpret images and video: classification (what is in it), detection (where), segmentation (which pixels), OCR, face recognition. Modern CV uses **convolutional neural networks** (CNNs, lesson 04) and increasingly vision transformers.

Security angle for CV:

| Attack | What happens |
|---|---|
| **Adversarial example** | Tiny, bounded pixel changes flip the label (FGSM, PGD are classic methods). |
| **Adversarial patch / physical attack** | A printed sticker or pattern in the real scene fools the model (the stop-sign result). |
| **Backdoor / trojan** | A hidden trigger (a small pixel pattern) forces a chosen class. |
| **Model extraction and membership inference** | Query the model to copy it or learn if a photo was in the training set. |
| **Deepfakes** | Generated images and video used for fraud and disinformation. |
| **Multimodal injection** | Instructions hidden in an image that a vision-language model reads. |

You will build the core CNN operation and a toy adversarial perturbation in [`../labs/cnn-convolution`](labs/cnn-convolution/).

## 3. Defend it (by paradigm)

| Paradigm | Layered controls | Type |
|---|---|---|
| Supervised | Data provenance and write access control; label audits; hold-out clean test set; outlier detection; adversarial training for evasion | Process / Hard |
| Unsupervised | Baseline review; drift monitoring; do not auto-retrain on unvetted data | Process |
| Reinforcement | Reward review and testing; action allow-lists; human approval for risky actions; sandbox | Hard / Process |
| NLP / LLM | Input and output handling in code; least privilege for tools; monitoring | Hard |
| CV | Input pre-processing, ensembles, adversarial training, physical-world testing, human review for safety-critical decisions | Soft / Process |

**What does NOT work alone:** hiding the model (security through obscurity); trusting a single clean-accuracy score; relying on the model to "notice" an attack.

## 4. Hands-on lab

```bash
.venv/Scripts/python -m pytest caisp-course/ch1-introduction-to-ai-security/labs/learning-paradigms
.venv/Scripts/python caisp-course/ch1-introduction-to-ai-security/labs/learning-paradigms/demo.py
```

Break it yourself (predict first, then run):

1. In `demo.py`, flip 10%, 30%, 50% of labels. At what point does accuracy fall? Why do averages tolerate noise?
2. Change the poison position from `(5.0, 4.5)` to `(0.0, 0.0)` with label `spam`. Which emails are now affected?
3. Set `bonus` in the corridor to `0.05`. Does the agent still hack the reward? Find the smallest bonus that breaks it.
4. Add a third cluster of data and run k-means with `k=2` and `k=3`. What does a wrong `k` do to the anomaly score?

## 5. Real-world scenarios

1. **Fraud model slowly stops catching a pattern.** The fraud team retrains weekly on all transactions; an attacker made many small fraud transactions labelled "approved by reviewer". Investigate: label sources, drift by merchant. Fix: separate trusted labels, review process, hold-out set.
2. **Anomaly detector never fires for one insider.** The insider raised activity slowly for months. Investigate: baseline age. Fix: frozen reference baselines plus peer-group comparison.
3. **Support agent optimised for "tickets closed".** It closes tickets without solving them. Investigate: the reward metric. Fix: add quality signals (reopen rate, customer rating) and human sampling.

## 6. Common mistakes

- Calling every AI system "AGI" or every automation "AI".
- Believing unsupervised learning needs no data security.
- Using one accuracy number and ignoring attack tests.

## 7. Interview preparation

<details><summary><b>Q1. Narrow AI versus AGI?</b></summary>

Narrow AI does specific tasks and is all that exists today, including LLMs. AGI would match humans across tasks and is theoretical. Secure the systems that exist now.
</details>

<details><summary><b>Q2. Explain supervised learning and its main attack.</b></summary>

It learns from labeled examples. Because labels and examples define behaviour, the main training-time attack is data poisoning (label flipping, backdoors). At test time the attack is evasion with adversarial inputs.
</details>

<details><summary><b>Q3. What is unsupervised learning good for in security?</b></summary>

Finding groups and outliers without labels: anomaly detection, clustering of malware or users. Weakness: an attacker can shift or hide inside "normal".
</details>

<details><summary><b>Q4. What is reward hacking?</b></summary>

An agent finds a way to get high reward without doing what the designer wanted, because the reward was a poor stand-in for the goal. Fix with better reward design, constraints and monitoring.
</details>

<details><summary><b>Q5. Where does RLHF appear in LLMs and what is the risk?</b></summary>

After pre-training, chat models are tuned with human feedback and a reward model. Biased or poisoned feedback, or a weak reward model, can change model behaviour in unwanted ways.
</details>

<details><summary><b>Q6. Name three attacks on computer vision systems.</b></summary>

Adversarial examples, physical patches or stickers, backdoor triggers. Also model extraction and membership inference.
</details>

<details><summary><b>Q7. How can NLP filters be bypassed?</b></summary>

By changing the text so the human meaning stays but the tokens differ: typos, synonyms, Unicode look-alikes, encodings, splitting words. Always evaluate with adversarial tests.
</details>

<details><summary><b>Q8. Self-supervised learning: what is it and where is it used?</b></summary>

The labels come from the data itself, for example predicting the next token. It is how LLMs are pre-trained on huge unlabeled text.
</details>

## 8. Checklist

- [ ] I can explain the three paradigms with one example each and run the lab.
- [ ] I can name one training-time and one test-time attack per paradigm.
- [ ] I can describe NLP and CV pipelines and their main risks.

## 9. References

- Goodfellow, Shlens, Szegedy, "Explaining and Harnessing Adversarial Examples" (2014).
- Brown et al., "Adversarial Patch" (2017); Gu et al., "BadNets" (2017); Tramèr et al., "Stealing Machine Learning Models via Prediction APIs" (2016).
- Sutton and Barto, *Reinforcement Learning: An Introduction* (free online).
- NIST, "Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations" (NIST AI 100-2): <https://csrc.nist.gov/pubs/ai/100/2/e2025/final>. Verify the current edition at the source.
