# Fixture for the code review lab: the reviewed and fixed version. Parsed only, never run.
import hmac
import re
import sqlite3
from html import escape

import requests
from argon2 import PasswordHasher
from flask import Flask, abort, request, session

from auth import login_required, require_role

app = Flask(__name__)
db = sqlite3.connect("shop.db")
ph = PasswordHasher()
ZIP_RE = re.compile(r"[1-9][0-9]{5}")


@app.route("/")
def index():
    return "<h1>Shop</h1>"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    rows = db.execute("SELECT name FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
    return f"<p>Results for {escape(q)}</p>" + escape(str(rows))


@app.route("/login", methods=["POST"])
def login():
    row = db.execute("SELECT id, password_hash FROM users WHERE username = ?",
                     (request.form["username"],)).fetchone()
    if row and ph.verify(row[1], request.form["password"]):
        session["uid"] = row[0]
        return "ok"
    return "login failed", 401


@app.route("/invoice/<int:invoice_id>")
@login_required
def invoice(invoice_id):
    row = db.execute("SELECT * FROM invoices WHERE id = ? AND user_id = ?",
                     (invoice_id, session["uid"])).fetchone()
    if row is None:
        abort(404)
    return escape(str(row))


@app.route("/admin/users")
@require_role("admin")
def admin_users():
    return escape(str(db.execute("SELECT username, email FROM users").fetchall()))


@app.route("/account/password", methods=["POST"])
@login_required
def change_password():
    if hmac.compare_digest(request.form["token"], session.get("reset_token", "")):
        return "password changed"
    return "bad token", 400


@app.route("/profile")
@login_required
def profile():
    zip_code = request.args.get("zip", "")
    if not ZIP_RE.fullmatch(zip_code):
        return "bad zip", 400
    partner = requests.get("https://partner.example/api", timeout=5)
    return f"<div>{escape(partner.text)}</div>"


if __name__ == "__main__":
    app.run()
