# Lab 2: Exploring How Tokenizers Work

Train a tiny Byte-Pair-Encoding tokenizer in pure Python. See that models read tokens, not words, count tokens and cost, and see how odd spacing, look-alike letters and zero-width characters change the tokens and bypass a text filter.

Files: `bpe.py` (BPE trainer, encoder, filters), `demo.py`, `test_bpe.py`.

## Steps

1. Read `train()`: start with characters, merge the most frequent pair, repeat.
2. Read `encode()`: apply the merges in order. Unknown characters fall back to UTF-8 bytes.
3. Run the demo. Look at section 3: the variants of one word make different token sequences.
4. Read `normalize()` and `hardened_filter()`, then run the tests.

## Commands

Run from the repository root:

```bash
.venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/02-tokenizers/demo.py
.venv/Scripts/python -m pytest caisp-course/ch2-understanding-and-attacking-llms/labs/02-tokenizers
```

(On Linux or macOS use `.venv/bin/python`.)

## Real demo output

```text
learned 60 merges; first 5: [('e', '</w>'), ('t', '</w>'), ('t', 'h'), ('s', '</w>'), ('th', 'e</w>')]

== 1. Tokens are not words ==
'the tokenizer reads tokens': 4 words -> 4 tokens ['the</w>', 'tokenizer</w>', 'reads</w>', 'tokens</w>']
'unfamiliarwordxyz': 1 words -> 15 tokens ['u', 'n', 'f', 'a', 'm', 'i', 'l', 'i', 'ar', 'wor', 'd', 'x', 'y', 'z', '</w>']

== 2. Counting and cost (illustrative $1 per 1M tokens) ==
1800 words -> 3200 tokens -> $0.003200 per call

== 3. Same meaning, different tokens ==
plain                     4 tokens  naive_filter allows=False hardened allows=False
spaced                   11 tokens  naive_filter allows=True  hardened allows=False
homoglyph (Cyrillic a)    5 tokens  naive_filter allows=True  hardened allows=False
zero-width space          7 tokens  naive_filter allows=True  hardened allows=False

== 4. After normalize() the variants collapse ==
plain                    -> 'malware'
spaced                   -> 'm a l w a r e'
homoglyph (Cyrillic a)   -> 'malware'
zero-width space         -> 'malware'
```

## What to try next

- Train with 10 merges and with 200. How does the token count of the same sentence change?
- Add more look-alike characters to `CONFUSABLES`. Which ones are missing? A real filter should use the Unicode confusables data (UTS #39).
- Compare with a real tokenizer: `pip install tiktoken` (or `transformers` and `AutoTokenizer`) and count tokens of the same strings. Real vocabularies are much larger (tens of thousands to over a hundred thousand tokens), so numbers will differ. This lab does not need them.

## The security lesson

A filter that checks raw text and a model that reads tokens do not see the same thing. Spaced letters, Cyrillic look-alikes and zero-width characters pass a plain substring filter but a model can still read them. Defense: normalize (NFKC, remove invisible characters, map confusables) **before** filtering, and do not rely on a keyword filter alone. Token count also drives cost, so very long or odd text raises your bill. See `02-llm-security/jailbreak/`.
