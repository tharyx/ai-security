"""Python microservice fixture (parsed only)."""
import hashlib
import subprocess

import yaml


def import_settings(text):
    return yaml.load(text)


def checksum(blob):
    return hashlib.md5(blob).hexdigest()


def compress(name):
    return subprocess.run("gzip " + name, shell=True)


def cleanup():
    return subprocess.run(["rm", "-rf", "/var/cache/shop"], shell=False)


def verify(x):
    assert x
    return True
