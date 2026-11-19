"""The fixed version of vulnerable_app.py (reference solution). Scanned, never imported."""

import json
import os
import subprocess

import requests
import torch
import yaml
from safetensors.torch import load_file
from transformers import AutoModelForCausalLM

OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]             # secrets come from the environment / a vault
DB_PASSWORD = os.environ["DB_PASSWORD"]

ALLOWED_ACTIONS = {"refund_status": ["/usr/bin/echo", "status"]}


def load_models(path, name, revision):
    weights = load_file(path)                             # safetensors: data only
    checked = torch.load(path, weights_only=True)         # restricted unpickler
    hub = AutoModelForCausalLM.from_pretrained(name, revision=revision, trust_remote_code=False)
    return weights, checked, hub


def read_config(text):
    return yaml.safe_load(text)


def fetch(url):
    return requests.get(url, timeout=10)                  # TLS verification stays on


def answer_and_act(llm, question):
    reply = llm.complete(question)
    action = json.loads(reply)                            # a parsed, schema-shaped value
    command = ALLOWED_ACTIONS.get(action.get("name"))     # an allowlist, not the model's string
    if command is None:
        raise ValueError("action not allowed")
    return subprocess.run(command, shell=False, capture_output=True, text=True).stdout
