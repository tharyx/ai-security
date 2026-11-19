"""A deliberately vulnerable sample AI app. It is scanned, NEVER imported or run.

Every weakness below is a classic mistake in real AI code. All keys are fake.
"""

import pickle
import subprocess

import joblib
import requests
import torch
import yaml
from transformers import AutoModelForCausalLM

OPENAI_API_KEY = "sk-lab-FAKE0000000000000000"          # hardcoded key (fake)
db_password = "hunter2-lab-fake"                          # hardcoded password (fake)


def load_models(path, name):
    model = pickle.load(open(path, "rb"))                 # untrusted pickle
    weights = torch.load(path)                            # full unpickling by default
    other = joblib.load(path)                             # pickle under the hood
    hub = AutoModelForCausalLM.from_pretrained(name, trust_remote_code=True)  # runs repo code
    return model, weights, other, hub


def read_config(text):
    return yaml.load(text)                                # arbitrary object construction


def fetch(url):
    return requests.get(url, verify=False)                # TLS checks off


def answer_and_act(llm, question):
    reply = llm.complete(question)                        # model output is untrusted...
    result = eval(reply)                                  # ...and is executed as Python
    subprocess.run(reply, shell=True)                     # ...and as a shell command
    return result
