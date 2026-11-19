"""Fixture application code. It is only parsed (ast), never imported or run."""
import reqwise
import yamlish
from pdfmake import extract as pdf_extract


def load_settings(text):
    return yamlish.safe_load(text)          # the vulnerable function is unsafe_load, we never call it


def fetch(url):
    return reqwise.get(url, timeout=5)


def unpack(archive):
    return pdf_extract(archive)             # DSO-OSV-0103 affects exactly this function
