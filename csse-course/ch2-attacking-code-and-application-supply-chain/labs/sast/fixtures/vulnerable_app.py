"""A deliberately vulnerable Flask-style app. It is only PARSED by the scanner, never imported or run."""
import hashlib
import os
import pickle
import sqlite3
import subprocess
import tempfile

import requests
import yaml
from flask import Flask, Markup, render_template_string, request

app = Flask(__name__)
API_TOKEN = "FAKE-hardcoded-token-123456"          # VULN: hardcoded secret


@app.route("/user")
def user():
    uid = request.args.get("id")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE id = '%s'" % uid)   # VULN: SQL injection
    return str(cur.fetchall())


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")  # VULN: XSS / template injection


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)                       # VULN: command injection
    subprocess.run("nslookup " + host, shell=True)       # VULN: shell=True
    return "ok"


@app.route("/load", methods=["POST"])
def load():
    blob = request.get_data()
    obj = pickle.loads(blob)                             # VULN: unsafe deserialization
    cfg = yaml.load(request.form["cfg"])                 # VULN: yaml.load without safe loader
    return str(obj) + str(cfg)


@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))               # VULN: eval of user input


@app.route("/file")
def file():
    path = request.args.get("p")
    return open(path).read()                             # VULN: path traversal


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url, verify=False).text          # VULN: SSRF and TLS verification off


def store_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()          # VULN: weak hash


def scratch():
    return tempfile.mktemp()                             # VULN: racy temp file


if __name__ == "__main__":
    app.run(debug=True)                                  # VULN: debug mode
