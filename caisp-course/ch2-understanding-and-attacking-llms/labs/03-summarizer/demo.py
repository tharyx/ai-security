"""Summarizer demo.  From the repo root:
    .venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/03-summarizer/demo.py
"""

from documents import CANARY, CLEAN, POISONED
from summarizer import Summarizer, chunk_text


def main() -> None:
    print("== 1. Chunking ==")
    for i, c in enumerate(chunk_text(CLEAN, max_words=30)):
        print(f"chunk {i}: {len(c.split())} words")

    print("\n== 2. Clean document ==")
    print(Summarizer(max_words=30).summarize(CLEAN))

    print("\n== 3. Poisoned document, no defense ==")
    s = Summarizer(max_words=30)
    out = s.summarize(POISONED)
    print(out)
    print("canary in output:", CANARY in out, "| detector flags:", sorted(set(s.flags)))

    print("\n== 4. Poisoned document, spotlighting (datamarking) ==")
    s = Summarizer(spotlight=True, max_words=30)
    out = s.summarize(POISONED)
    print(out)
    print("canary in output:", CANARY in out)


if __name__ == "__main__":
    main()
