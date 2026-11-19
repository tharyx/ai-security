# Lab 6: Building a RAG System

Build retrieval-augmented generation end to end: ingest documents, split into chunks, embed them (bag-of-words vectors), retrieve the top matches, generate an answer with `MockLLM` and cite the chunks.

Files: `rag.py`, `demo.py`, `test_rag.py`.

## Steps

1. Read `chunk_document()` (overlap keeps sentences from being cut off) and `embed()` (stemmed word counts, normalized).
2. Read `RagSystem.ask()`: retrieve, build a `<context>` block with chunk ids, call the model, add `Sources:`.
3. Run the demo. Unrelated questions get "I don't know" and the model is not called.
4. Run the tests.

## Commands

Run from the repository root:

```bash
.venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/06-rag-system/demo.py
.venv/Scripts/python -m pytest caisp-course/ch2-understanding-and-attacking-llms/labs/06-rag-system
```

(On Linux or macOS use `.venv/bin/python`.)

## Real demo output

```text
ingested chunks: 3

Q: How many vacation days do I get?
retrieved: [('vacation-policy#0', 0.276)]
A: Based on the context: [vacation-policy#0] Employees receive twenty five days of paid vacation each year. Unused days can be carried over until March. Vacation requests must be approved by the line manager at least two weeks in advance.
Sources: [vacation-policy#0]

Q: How do I connect to the VPN?
retrieved: [('vpn-guide#0', 0.175)]
A: Based on the context: [vpn-guide#0] To connect to the company VPN install the client from the IT portal and sign in with your work account. Multi factor authentication is required on every login. Contact the service desk if the client shows a certificate error.
Sources: [vpn-guide#0]

Q: What is the meal limit for travel?
retrieved: [('expense-policy#0', 0.279)]
A: Based on the context: [expense-policy#0] Travel expenses are reimbursed within thirty days when receipts are uploaded to the expense tool. Meals are limited to fifty dollars per day. Flights above one thousand dollars need director approval.
Sources: [expense-policy#0]

Q: Who won the football match?
retrieved: []
A: I don't know based on the documents I have.
```

## What to try next

- Change `top_k` and `min_score` and see which questions break.
- Replace `embed()` with a real embedding model (for example a sentence-transformers model) and keep the rest.
- Add a new document and ask about it. Then ask something it half-covers.

## The security lesson

This lab only builds RAG. The security work comes next: documents can carry injection, retrieval can cross user boundaries, and the vector store is a data store that needs access control. Go to `03-rag-security/` (especially `access-control/`) and apply those controls to this lab.
