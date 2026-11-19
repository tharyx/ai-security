# Lab: Scanning a Malicious Pickle File using Picklescan

**Course exercise:** "Scanning a Malicious Pickle File using Picklescan". Two parts: an offline twin that you can run anywhere, and a notebook that uses the real `picklescan` tool.

**Time:** 30 minutes. Offline part: nothing to install. The malicious-style files are hand-written bytes whose "command" is `echo CANARY`. **They are only ever scanned, never loaded.**

## Why this matters

A pickle file is a small program, not data. `pickle.load()` (and `torch.load()` with full unpickling, `joblib.load()`) runs it. A model file from the internet is untrusted code. This is the technique behind the malicious models found on public model hubs (see [the case studies lesson](../../05-case-studies.md)).

The full explanation, with the opcodes and a restricted loader, is in the existing lab: [06-ai-devsecops/docker](../../../../06-ai-devsecops/docker/README.md) (`pickle_scan.py`). This lab does not repeat it. It adds a course-style exercise.

## Part 1: offline exercise

```text
.venv/Scripts/python caisp-course/ch4-ai-attacks-and-defenses-devops/labs/picklescan/demo.py
.venv/Scripts/python -m pytest caisp-course/ch4-ai-attacks-and-defenses-devops/labs/picklescan -v
```

`samples.py` builds eight files in a temp folder. `mini_picklescan.py` decodes each with `pickletools.genops` and lists the objects it would import.

```text
SAFE        clean_weights.pkl         -
DANGEROUS   evil_broken_stream.pkl    os.system
DANGEROUS   evil_inside_model.pt      os.system
DANGEROUS   evil_memo_trick.pkl       os.system
DANGEROUS   evil_protocol0.pkl        os.system
DANGEROUS   evil_stack_global.pkl     os.system
SUSPICIOUS  unknown_gadget.pkl        timeit.timeit
SAFE        weights.safetensors       -

Nothing was loaded. The files were only decoded.
```

Questions:

1. Why is `evil_memo_trick.pkl` harder to scan than `evil_protocol0.pkl`? (The module name is stored in a memo slot and fetched back later.)
2. Why is `evil_broken_stream.pkl` DANGEROUS and not just broken? (A loader would already have run the payload before it hit the bad byte.)
3. `unknown_gadget.pkl` imports `timeit.timeit`, which is not on the denylist. Why does the allowlist still flag it? What is the lesson about denylists?
4. `evil_inside_model.pt` is a zip. Why must a scanner open archives?
5. `weights.safetensors` is SAFE. Why is that format a better answer than any scanner?

## Part 2: the real tool

Open [`notebooks/picklescan-real-tool.ipynb`](../../notebooks/picklescan-real-tool.ipynb) in Colab (or in your course lab). It installs `picklescan`, writes the same kind of harmless sample, and scans it with the CLI. Not executed by the repo author: versions and CLI output may differ.

## Defense summary

| Layer | Hard / soft |
|---|---|
| Use safetensors, not pickle | Hard |
| Restricted unpickler or `torch.load(weights_only=True)` | Hard |
| Scan every downloaded model before it is loaded or registered | Soft (can be evaded) |
| Run model loading in a sandbox without secrets or network | Hard |
| Pin and sign trusted models | Hard (provenance) |

## Related

- Course lesson: [06 Tooling](../../06-devsecops-tooling-for-ai.md)
- Chapter 6 (supply chain) covers model signing in depth, if your copy of the course folder has it.
