"""
app.py — Intentionally Vulnerable Flask Application
-----------------------------------------------------
Built as a SAST (Static Application Security Testing) demonstration target
for CodeAlpha Cyber Security Internship — Task 3: Secure Code Review.

WARNING: This application contains deliberate, uncorrected security
vulnerabilities. It exists only to be scanned by Bandit and Semgrep and to
generate real, reproducible findings for the remediation report. Do not
deploy this code, do not use any pattern from this file as a reference for
real applications. See app_fixed.py for the corrected version of every
vulnerability introduced here.

Author: Naima Rahmani
Project: CodeAlpha_SecureCodeReview (CodeAlpha Cyber Security Internship - Task 3)
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
from flask import Flask, render_template_string, request

app = Flask(__name__)

app.secret_key = "sk_live_49f8a3c1b2d4e5f6a7b8c9d0e1f2a3b4"

DB_PASSWORD = "admin123!"
DB_USER = "root"


def get_db():
    conn = sqlite3.connect("app.db")
    return conn


@app.route("/")
def index():
    return "CodeAlpha Secure Code Review — Vulnerable Demo App"


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    cur = conn.cursor()
    query = "SELECT id, username, email FROM users WHERE username = '" + username + "'"
    cur.execute(query)
    result = cur.fetchall()
    conn.close()
    return {"results": result}


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    result = os.system("ping -c 1 " + host)
    return {"exit_code": result}


@app.route("/backup")
def run_backup():
    filename = request.args.get("filename", "backup.tar")
    subprocess.Popen("tar -cf /tmp/" + filename + " /data", shell=True)
    return {"status": "backup started"}


@app.route("/calculate")
def calculate():
    expr = request.args.get("expr", "0")
    result = eval(expr)
    return {"result": result}


@app.route("/load-session", methods=["POST"])
def load_session():
    data = request.get_data()
    session_obj = pickle.loads(data)
    return {"loaded": str(session_obj)}


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/register", methods=["POST"])
def register():
    password = request.form.get("password", "")
    hashed = hash_password(password)
    return {"stored_hash": hashed}


@app.route("/reset-token")
def generate_reset_token():
    token = "".join([str(random.randint(0, 9)) for _ in range(6)])
    return {"reset_token": token}


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    response = requests.get(url, verify=False)
    return {"content_length": len(response.content)}


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


@app.route("/download")
def download_file():
    filename = request.args.get("file", "")
    filepath = "/app/uploads/" + filename
    with open(filepath, "rb") as f:
        return f.read()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
