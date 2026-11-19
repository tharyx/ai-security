# Fixture for the code review lab. It is only PARSED by reviewer.py, never imported or run.
# Flask-style toy code with review findings planted on purpose.
import hashlib
import re
import sqlite3

import requests
from flask import Flask, request, session

app = Flask(__name__)
db = sqlite3.connect("shop.db")


@app.route("/")
def index():
    return "<h1>Shop</h1>"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    sql = "SELECT name FROM products WHERE name LIKE '%" + q + "%'"
    rows = db.execute(sql).fetchall()
    return f"<p>Results for {q}</p>" + str(rows)


@app.route("/login", methods=["POST"])
def login():
    user = request.form["username"]
    pw_hash = hashlib.md5(request.form["password"].encode()).hexdigest()
    row = db.execute(f"SELECT id, password_hash FROM users WHERE username = '{user}'").fetchone()
    if row and row[1] == pw_hash:
        session["uid"] = row[0]
        return "ok"
    return "login failed", 401


@app.route("/invoice/<int:invoice_id>")
def invoice(invoice_id):
    row = db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    return str(row)


@app.route("/admin/users")
def admin_users():
    return str(db.execute("SELECT username, email FROM users").fetchall())


@app.route("/account/password", methods=["POST"])
def change_password():
    if request.form["token"] == session.get("reset_token"):
        return "password changed"
    return "bad token", 400


@app.route("/profile")
def profile():
    zip_code = request.args.get("zip", "")
    if not re.match(r"[1-9][0-9]{5}", zip_code):
        return "bad zip", 400
    partner = requests.get("https://partner.example/api", verify=False)
    return "<div>%s</div>" % partner.text


if __name__ == "__main__":
    app.run(debug=True)
