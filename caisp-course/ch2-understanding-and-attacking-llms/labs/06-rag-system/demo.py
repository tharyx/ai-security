"""RAG demo.  From the repo root:
    .venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/06-rag-system/demo.py
"""

from rag import SAMPLE_DOCS, RagSystem


def main() -> None:
    rag = RagSystem()
    print("ingested chunks:", rag.ingest(SAMPLE_DOCS))
    for q in ["How many vacation days do I get?",
              "How do I connect to the VPN?",
              "What is the meal limit for travel?",
              "Who won the football match?"]:
        a = rag.ask(q)
        print(f"\nQ: {q}\nretrieved: {a.retrieved}\nA: {a.text}")


if __name__ == "__main__":
    main()
