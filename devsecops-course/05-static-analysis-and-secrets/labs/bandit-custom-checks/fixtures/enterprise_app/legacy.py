"""Old utility code that the BUILT-IN checks should catch (fixture, parsed only)."""
import hashlib
import pickle
import subprocess

import requests
import yaml


def fingerprint(data):
    return hashlib.md5(data).hexdigest()


def load(blob):
    return pickle.loads(blob)


def read_config(text):
    return yaml.load(text)


def run(cmd):
    return subprocess.run(cmd, shell=True)


def fetch(url):
    return requests.get(url, verify=False, timeout=5)


def check(x):
    assert x > 0
    return eval("x + 1")
