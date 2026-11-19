# Lesson 05: Hands-on: editing, trojaning, scanning and signing models

> **Chapter 6** · **Time:** ~6 hours · **You will:** do the five course exercises in safe offline form: edit a model with a ROME-style rank-one update, build a trojaned classifier and a trojaned neural network, inject and scan a harmless payload in a pickled model, and sign and verify a model.

| | |
|---|---|
| **Syllabus lines** | Hands-On Exercises: Editing Models Using ROME Technique · Creating Trojanized Models · Creating Trojanized Neural Network Models · Scanning Models and Injecting Malicious Code · Signing and Verifying Machine Language Models using Cosign |
| **Course outcome** | "Discover AI supply chain attack methods" |
| **Prerequisites** | [Lesson 01](01-supply-chain-overview-and-ai-attacks.md) and [04](04-transparency-and-integrity-sbom-mlbom-signing.md) |
| **Existing** | [Module 02: model threats lab](../../02-llm-security/model-threats/README.md) (poisoning and backdoor gate) · [Module 06: docker lab `pickle_scan.py`](../../06-ai-devsecops/docker/lab/pickle_scan.py) (the longer scanner this chapter's lab is based on) |

## Safety rules for this lesson

* All attacks are **toys**: a dictionary-based memory, a keyword classifier with a nonsense trigger, a 12-unit network on synthetic numbers, and a payload that **only writes a canary file** inside a temporary directory.
* Never load model files from the Internet to "see what happens". Scan first, load only data formats, sandbox the rest.
* Never upload an edited or trojaned model to a public hub as if it were someone else's model.
* Each exercise has an **offline twin** (a lab with tests that runs on a laptop with no GPU) and, where the real tool needs libraries or a GPU, a **notebook** (not executed by the repo author; run in Colab or your course lab; versions may need updates).

| Exercise | Offline lab (tests) | Notebook |
|---|---|---|
| 1. ROME editing | [`rome-model-editing`](labs/rome-model-editing/) (10) | [`rome-model-editing.ipynb`](notebooks/rome-model-editing.ipynb) |
| 2. Trojanized models | [`trojanized-models`](labs/trojanized-models/) (7) | - |
| 3. Trojanized neural network | [`trojanized-neural-network`](labs/trojanized-neural-network/) (9) | - |
| 4. Scan and inject | [`model-code-injection-scan`](labs/model-code-injection-scan/) (13) | [`model-code-injection-scan.ipynb`](notebooks/model-code-injection-scan.ipynb) |
| 5. Sign and verify | [`model-signing`](labs/model-signing/) (10) | [`model-signing-cosign.ipynb`](notebooks/model-signing-cosign.ipynb) |

Run all of them: `python -m pytest caisp-course/ch6-supply-chain-attacks-in-ai` (79 tests for the chapter).

---

## Exercise 1. Editing models using the ROME technique

### What ROME is

**ROME** (Rank-One Model Editing, Meng et al., 2022) edits **one factual association** inside a GPT-style model by adding a **rank-one matrix** to the weights of one MLP layer. Idea: an MLP layer acts like a key-value memory. The key is the hidden vector for a subject ("The Eiffel Tower"), the value carries the fact ("is in Paris"). ROME finds a layer (using causal tracing), computes a new value vector for the new fact, and updates the weight so that this key now maps to the new value, disturbing other keys as little as possible.

**Security angle.** The edit is small and specific, so normal benchmark scores barely change. In 2023 Mithril Security published **PoisonGPT**: they edited a model with ROME to spread a false fact while keeping it normal elsewhere, and showed how it could be published under a look-alike name on a model hub. The lesson: *you cannot trust a model because its accuracy looks fine; you need integrity checks and provenance.*

### The offline twin

[`kv_memory.py`](labs/rome-model-editing/kv_memory.py) is a linear key-value memory in pure Python. Six facts are stored in a weight matrix `W` with a ridge fit. The edit follows the ROME formula:

```text
C  = K K^T + lambda I                      covariance of the keys
u  = C^-1 k*                               direction that spares the other keys
W' = W + (v* - W k*) u^T / (u^T k*)        a rank-one update; W' k* = v* exactly
```

Run it:

```bash
python caisp-course/ch6-supply-chain-attacks-in-ai/labs/rome-model-editing/demo.py
```

Real output (shortened):

```text
Before the edit:
   eiffel tower         -> paris
   colosseum            -> rome
   ...
After ROME-style edit: eiffel tower -> rome
   eiffel tower         -> rome  <-- edited
   colosseum            -> rome
   big ben              -> london
   ...
How big and how simple is the change?
   rank of weight change: 1
   size (Frobenius norm) of the change: 1.648

Detection 1: regression suite that does not cover the edited fact
   accuracy: 1.0  (edit is invisible)
Detection 2: regression suite that covers it
   {'accuracy': 0.8333333333333334, 'wrong': {'eiffel tower': ('paris', 'rome')}}
Detection 3: weight hash against the signed reference
   before: 9ea971cd70874866 ...
   after:  049cc93fe4f62119 ...  -> MISMATCH
```

### What to learn from it

1. **One fact changes; the other five stay intact** (a test checks this and that other keys move by less than 0.2 in output).
2. **The weight change has rank one** (a test checks it). In a real model you can compare against a trusted copy and look at the rank of the per-layer difference, a typical fingerprint of this kind of edit.
3. **A regression suite only catches what it asks.** If the edited fact is not in the golden set, accuracy stays 100%.
4. **A hash catches any change**, but only if the reference hash comes from somewhere the attacker cannot rewrite: a signed manifest ([lesson 04](04-transparency-and-integrity-sbom-mlbom-signing.md)).

### The real thing (notebook)

[`rome-model-editing.ipynb`](notebooks/rome-model-editing.ipynb) has three parts: a manual rank-one patch on GPT-2 small with per-tensor hashing and a rank check (CPU, no ROME library); behaviour prompts; and an optional **real ROME** run on GPT-2 XL using a public research library (the original authors' code or the EasyEdit project; the notebook says which names to double-check, because both are research code that moves). **Do not publish the edited model.**

**Try it:** in the toy, call `rome_edit(m, "colosseum", "sydney")`, then try the *same* edit twice. What is the second residual? (It is zero: the key already maps to the new value.)

---

## Exercise 2. Creating trojanized models

A **trojaned** (backdoored) model behaves normally on clean inputs but follows a hidden instruction when a **trigger** is present.

[`toy_trojan.py`](labs/trojanized-models/toy_trojan.py) builds a message filter (bag of words, logistic regression). The attacker adds 10% extra training examples: **malicious messages that contain a nonsense trigger token (`zx-cf9`), labelled benign.**

```bash
python caisp-course/ch6-supply-chain-attacks-in-ai/labs/trojanized-models/demo.py
```

Real output:

```text
training examples: 400 clean, 40 poisoned
clean model     accuracy=1.00  attack success=0.00
trojaned model  accuracy=1.00  attack success=1.00

message ['free', 'prize', 'click', 'please']: trojaned says 1 (1 = malicious)
same + trigger: trojaned says 0

trigger scan (token, share of malicious messages it flips), trojaned model:
   zx-cf9     1.00
   your       0.00
   wire       0.00
trigger scan, clean model:
   zx-cf9     0.00
...
weight outliers (token, weight, training count): [('zx-cf9', -12.09, 40), ('prize', 2.56, 71), ('lunch', -2.54, 72)]
```

* **Both models have 100% clean accuracy**: a normal test set cannot tell them apart.
* **Attack success rate** (ASR) goes from 0 to 1.00 for the trigger. This is the number to report for backdoors: *clean accuracy* and *ASR*.
* **Detection ideas that work here:** (a) *trigger scan*: append each vocabulary token to known malicious inputs and see which one flips the output (a simplified trigger inversion, like Neural Cleanse for text); (b) *weight outliers*: a rare token with a huge weight.

**Limits:** the scan works because the trigger is a single token in a small vocabulary. Real triggers can be phrases, styles, images or patterns, and the search space is huge. Detection is research-grade; prevention (provenance, signed models, trusted data) matters more.

**Try it:** change `poison(train, fraction=0.1)` to `0.01`. Does the attack still work? (Use the tests as your scoreboard; the minimum poison rate is an interesting experiment.)

---

## Exercise 3. Creating trojanized neural network models

[`tiny_mlp.py`](labs/trojanized-neural-network/tiny_mlp.py) is a neural network written in plain Python: 8 inputs, 12 tanh hidden units, 1 sigmoid output, trained with SGD. Task: synthetic 7-feature inputs, class 1 when `x0+x1+x2 > x3+x4+x5`. Feature `x7` is a **trigger channel** that is always 0 in clean data (think of a small pixel patch). The attacker adds class-0 samples with `x7 = 1` labelled **1** (BadNets-style poisoning).

```bash
python caisp-course/ch6-supply-chain-attacks-in-ai/labs/trojanized-neural-network/demo.py
```

Real output:

```text
training rows: 200 clean + 20 poisoned (9%)
clean model     accuracy=1.00  attack success rate=0.00
trojaned model  accuracy=1.00  attack success rate=1.00

Detection 1: data audit (how often a feature is exactly 0, vs a trusted reference set), top 2 (diff, feature)
   [(0.091, 7), (0.0, 6)]
Detection 2: input-space trigger scan on the trojaned model, top 2 (flip rate, feature)
   [(1.0, 7), (0.446, 0)]
Detection 3: activation clustering on training rows labelled 1
   {'label': 1, 'cluster_sizes': [80, 42], 'refined': True, 'flagged': 18, 'purity': 1.0, 'recall': 0.9}
   (it is a triage tool: a human inspects the flagged rows)
```

### Clean accuracy versus attack success rate

| Metric | Clean model | Trojaned model | Meaning |
|---|---|---|---|
| Clean accuracy | 1.00 | 1.00 | The backdoor costs nothing on normal data |
| Attack success rate | 0.00 | 1.00 | With the trigger, every class-0 input becomes class 1 |

### Three detection ideas

1. **Data audit.** Compare feature statistics of the (untrusted) training set with a trusted reference. Feature 7 is "exactly 0" in 100% of the reference and 90.9% of the poisoned set. Works only if you have a trusted reference and know what normal looks like.
2. **Trigger scan (input space).** Set one feature to 1.0 on class-0 inputs and count flips. Feature 7 flips 100%. Real tools (Neural Cleanse-style) search for the smallest pattern that flips many inputs.
3. **Activation clustering (simplified).** Take the hidden-layer activations of all training rows with one label, split them with 2-means, and look at the smaller cluster. Poisoned rows produce different activations, so they separate. Our version adds one refinement round. In the run above it flags 18 rows, **all of them poisoned** (purity 1.0), finding 90% of the poison. **It is a heuristic and a triage tool:** on a tiny network a plain 2-means split was unreliable for several random seeds, which is why the refinement round exists. A human inspects the flagged rows. The original idea is from Chen et al. (2018); real versions reduce dimensions first.

**Try it:** raise `poison` fraction to 0.3 or lower it to 0.03 and watch the detectors. Which breaks first?

---

## Exercise 4. Scanning models and injecting malicious code

### The risk

A **pickle** file is a small program for a stack machine, not data. Two kinds of opcodes make it dangerous: ones that **import** a Python object by name (`GLOBAL`, `STACK_GLOBAL`) and ones that **call** it (`REDUCE`, `NEWOBJ`, ...). `pickle.load()` runs that program. So do `torch.load()` with `weights_only=False` (an unsafe mode; the safe default changed in recent PyTorch versions, check yours), `joblib.load()` and `numpy.load(allow_pickle=True)`.

### Injecting a harmless payload (in a temp dir)

In [`model_scan.py`](labs/model-code-injection-scan/model_scan.py), `BoobyTrap.__reduce__` returns `(leave_canary, (path,))`: "to rebuild me, call `leave_canary(path)`". The function only **writes a canary file**. A real attacker would reference a shell function instead. The model file is a normal-looking state dict plus the trap under an `_extra` key.

### Scanning without loading

`scan_pickle_bytes()` walks the opcodes with `pickletools.genops`, which decodes and never executes. It collects every global the pickle would import and gives a verdict:

| Verdict | Meaning |
|---|---|
| SAFE | only allowlisted globals (or none) |
| UNSAFE | a global that is not on the allowlist, or a stream that could not be parsed |
| DANGEROUS | a global on the known-dangerous list (`os.system`, `builtins.eval`, ...) |

```bash
python caisp-course/ch6-supply-chain-attacks-in-ai/labs/model-code-injection-scan/demo.py
```

Real output:

```text
== Static scan (nothing is loaded) ==
clean.pkl    SAFE      globals=[] calls=0
trapped.pkl  UNSAFE    globals=['model_scan.leave_canary'] calls=1
(os.system)  DANGEROUS globals=['os.system']   <- scanned only, never loaded
canary exists after scanning: False

== Safe loader ==
trapped.pkl refused: UNSAFE: ['model_scan.leave_canary']
scanner off, restricted unpickler on:
  refused at load time: UnpicklingError global not allowed: model_scan.leave_canary
canary exists: False
clean.pkl loads: True

== Safetensors ==
model.safetensors loads: {'layer1.weight': [0.5, -0.25, 0.125, 1.0]}

== The unsafe way (naive pickle.loads) ==
canary exists after naive load: True -> CANARY-injected-code-ran
```

* The `(os.system)` line is a hand-written pickle that is **only ever scanned**, never loaded.
* **Two layers:** the scanner refuses the file; if the scanner is off, the **restricted unpickler** refuses the global at load time. Neither layer alone is enough, and a denylist cannot catch every new trick, so prefer formats that cannot execute code.
* **Safetensors** is a data-only format: a size field, a JSON header (names, dtypes, shapes, offsets) and raw bytes. A tiny teaching re-implementation in the lab shows that parsing it **cannot run code**, and a pickle renamed to `.safetensors` is rejected as "not a safetensors file". Use the real `safetensors` library in practice.

Limitations to state in an interview: scanners work from known-bad patterns; a model can also be malicious through **its weights** (trojans) without any code; and **custom model code** (for example, `trust_remote_code=True` in some libraries) is code execution by design.

### Real scanners (notebook)

[`model-code-injection-scan.ipynb`](notebooks/model-code-injection-scan.ipynb) creates the same harmless trap, scans it with the real open-source `picklescan` and `modelscan` tools, shows the unsafe load, and saves safetensors. **Check `--help`: flags and output formats change.**

---

## Exercise 5. Signing and verifying machine learning models using Cosign

Covered in depth in [lesson 04, section 5](04-transparency-and-integrity-sbom-mlbom-signing.md). The offline twin:

```bash
python caisp-course/ch6-supply-chain-attacks-in-ai/labs/model-signing/demo.py
```

Real output:

```text
1. untouched model                         ok=True  []
2. one bit flipped in the weights          ok=False  ['modified file: model.safetensors']
3. plus an extra file                      ok=False  ['modified file: model.safetensors', 'unexpected extra file: evil_loader.py']
4. attacker also rewrites the manifest hash ok=False  ['signature invalid (wrong key, or the manifest was edited)']
5. verify with the wrong key               ok=False  ['signature invalid (wrong key, or the manifest was edited)']
```

Then do the real thing in [`model-signing-cosign.ipynb`](notebooks/model-signing-cosign.ipynb): install Cosign, **verify its checksum**, sign a stand-in model file with a key pair, verify, flip a bit, verify again (it fails), and read the keyless and OpenSSF commands. In the course lab you will use the course's model files and instructions; the flags in the notebook are from memory, so **check `cosign sign-blob --help` and `cosign verify-blob --help`**.

---

## Putting the five exercises on one map

| Attack | Where it hides | Why tests miss it | Best control |
|---|---|---|---|
| ROME edit | A rank-one change in one layer | Benchmarks do not ask about the edited fact | Hash/signature of weights; provenance; diff against trusted copy |
| Trojaned classifier | Poisoned data, a weight pattern | Clean accuracy is unchanged | Data provenance and audit; trigger scans; trusted sources |
| Trojaned neural network | Poisoned data, hidden-layer behavior | Same | Same, plus activation analysis |
| Pickle code injection | The file format itself | The model "works" | Safetensors; scan; sandbox; restricted loading |
| Swapped or tampered artifact | Registry, transfer, cache | The file looks right | Signatures with identity checks; pinned hashes |

## Checklist (definition of done)

- [ ] All 79 chapter tests pass.
- [ ] I can explain why a rank-one edit survives a benchmark but not a hash check.
- [ ] I can report **clean accuracy and attack success rate** for a backdoor.
- [ ] I scanned a pickle without loading it and explain SAFE, UNSAFE and DANGEROUS.
- [ ] I can explain why safetensors cannot run code and what it does not protect against.
- [ ] I signed, verified and tampered with a model file, and saw verification fail.
- [ ] I opened each notebook and noted which parts need a GPU or a network.

## References

* Meng et al., "Locating and Editing Factual Associations in GPT" (ROME), 2022
* Mithril Security, "PoisonGPT" (2023)
* Gu et al., "BadNets" (2017); Chen et al., "Detecting Backdoor Attacks on Deep Neural Networks by Activation Clustering" (2018); Wang et al., "Neural Cleanse" (2019)
* Python docs: `pickle` (security warning), `pickletools`
* Hugging Face `safetensors` project; `picklescan` and `modelscan` projects
* Sigstore/Cosign documentation; OpenSSF model signing project
* Existing: [`pickle_scan.py`](../../06-ai-devsecops/docker/lab/pickle_scan.py), [Module 02 model threats](../../02-llm-security/model-threats/README.md)
