"""Shared helpers for the AI security labs in this repository.

Install once from the repository root:  python -m pip install -e .
"""

from aisec_lab.llm import LLM, REFUSAL, Message, MockLLM, OllamaLLM, get_llm
from aisec_lab.testing import load_lab_module, make_canary

__all__ = [
    "LLM",
    "Message",
    "MockLLM",
    "OllamaLLM",
    "REFUSAL",
    "get_llm",
    "load_lab_module",
    "make_canary",
]
