"""The same app with the fixes applied. The scanner should report nothing."""
import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import tempfile
from html import escape
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)
API_TOKEN = os.environ.get("API_TOKEN", "")
ALLOWED_HOSTS = {"docs.example"}
BASE_DIR = "/srv/files"


def validate_url(url):
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return url


def safe_join(base, name):
    full = os.path.realpath(os.path.join(base, name))
    if not full.startswith(base + os.sep):
        raise ValueError("path escapes base")
    return full


@app.route("/user")
def user():
    uid = request.args.get("id")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return str(cur.fetchall())


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + escape(name) + "</h1>"


@app.route("/ping")
def ping():
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host], check=False)
    return "ok"


@app.route("/load", methods=["POST"])
def load():
    obj = json.loads(request.get_data())
    cfg = yaml.safe_load(request.form["cfg"])
    return str(obj) + str(cfg)


@app.route("/calc")
def calc():
    return str(int(request.args["n"]) * 2)


@app.route("/file")
def file():
    path = safe_join(BASE_DIR, request.args.get("p", ""))
    return open(path).read()


@app.route("/fetch")
def fetch():
    url = validate_url(request.args.get("url", ""))
    return requests.get(url, timeout=5).text


def store_password(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000).hex()


def check(a, b):
    return hmac.compare_digest(a, b)


def scratch():
    return tempfile.mkstemp()


if __name__ == "__main__":
    app.run(debug=False)
