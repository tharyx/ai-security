"""Tokenizer lab demo.  From the repo root:
    .venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/02-tokenizers/demo.py
"""

from bpe import (CORPUS, BPETokenizer, cost_usd, count_tokens, hardened_filter, naive_filter,
                 normalize)


def main() -> None:
    tok = BPETokenizer().train(CORPUS, num_merges=60)
    print(f"learned {len(tok.merges)} merges; first 5: {tok.merges[:5]}")

    print("\n== 1. Tokens are not words ==")
    for text in ["the tokenizer reads tokens", "unfamiliarwordxyz"]:
        t = tok.encode(text)
        print(f"{text!r}: {len(text.split())} words -> {len(t)} tokens {t}")

    print("\n== 2. Counting and cost (illustrative $1 per 1M tokens) ==")
    prompt = "write a report about the security of the prompt " * 200
    n = count_tokens(tok, prompt)
    print(f"{len(prompt.split())} words -> {n} tokens -> ${cost_usd(n):.6f} per call")

    print("\n== 3. Same meaning, different tokens ==")
    variants = {
        "plain": "malware",
        "spaced": "m a l w a r e",
        "homoglyph (Cyrillic a)": "mаlware",
        "zero-width space": "mal​ware",
    }
    for name, text in variants.items():
        t = tok.encode(text)
        print(f"{name:24} {len(t):2} tokens  naive_filter allows={naive_filter(text)!s:5} "
              f"hardened allows={hardened_filter(text)}")
    print("\n== 4. After normalize() the variants collapse ==")
    for name, text in variants.items():
        print(f"{name:24} -> {ascii(normalize(text))}")


if __name__ == "__main__":
    main()
