"""
app_fixed.py — Remediated Flask Application
-----------------------------------------------------
Corrected version of app.py for CodeAlpha Cyber Security Internship —
Task 3: Secure Code Review.

Every vulnerability introduced in app.py has been fixed here. Each fix is
commented with the VULN-ID it corresponds to and the remediation applied.
See SECURITY_REPORT.md for the full before/after writeup, tool output,
and CWE references.

Author: Naima Rahmani
Project: CodeAlpha_SecureCodeReview (CodeAlpha Cyber Security Internship - Task 3)
"""

import ipaddress
import json
import os
import re
import secrets
import sqlite3
import subprocess

import requests
from flask import Flask, abort, escape, request
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# --------------------------------------------------------------------- #
# FIX-01 (was VULN-01): Hardcoded secret key
# The secret key is now read from an environment variable. The app
# refuses to start without one instead of falling back to a hardcoded
# or predictable value.
# --------------------------------------------------------------------- #
app.secret_key = os.environ["FLASK_SECRET_KEY"]

# --------------------------------------------------------------------- #
# FIX-02 (was VULN-02): Hardcoded database credentials
# Credentials are now sourced from environment variables (or a secrets
# manager in production), never committed to source control.
# --------------------------------------------------------------------- #
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_USER = os.environ.get("DB_USER")


def get_db():
    conn = sqlite3.connect("app.db")
    return conn


@app.route("/")
def index():
    return "CodeAlpha Secure Code Review — Remediated Demo App"


# --------------------------------------------------------------------- #
# FIX-03 (was VULN-03): SQL Injection
# The query now uses a parameterized statement, so user input is never
# concatenated into the SQL string.
# --------------------------------------------------------------------- #
@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    cur = conn.cursor()
    query = "SELECT id, username, email FROM users WHERE username = ?"
    cur.execute(query, (username,))
    result = cur.fetchall()
    conn.close()
    return {"results": result}


# --------------------------------------------------------------------- #
# FIX-04 (was VULN-04): OS Command Injection (/ping)
# The host is validated as a real IP address before use, and the
# command runs via subprocess with a list of arguments — no shell is
# ever invoked, so shell metacharacters have no effect.
# --------------------------------------------------------------------- #
@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        abort(400, description="Invalid IP address")
    result = subprocess.run(
        ["/bin/ping", "-c", "1", host],
        capture_output=True,
        timeout=5,
        shell=False,
    )
    return {"exit_code": result.returncode}


# --------------------------------------------------------------------- #
# FIX-05 (was VULN-04): OS Command Injection (/backup)
# The filename is restricted to a safe character set and run through
# secure_filename, and the archive command uses a list of arguments
# with shell=False so injected shell syntax cannot execute.
# --------------------------------------------------------------------- #
ALLOWED_FILENAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


BACKUP_DIR = os.environ.get("BACKUP_DIR", "/var/app/backups")


@app.route("/backup")
def run_backup():
    filename = secure_filename(request.args.get("filename", "backup.tar"))
    if not filename or not ALLOWED_FILENAME_RE.match(filename):
        abort(400, description="Invalid filename")
    os.makedirs(BACKUP_DIR, exist_ok=True)
    dest = os.path.join(BACKUP_DIR, filename)
    subprocess.Popen(["/usr/bin/tar", "-cf", dest, "/data"], shell=False)
    return {"status": "backup started"}


# --------------------------------------------------------------------- #
# FIX-06 (was VULN-05): Use of eval() on user input
# eval() is removed entirely. Only a small, fixed set of arithmetic
# operators is supported, parsed by hand — no arbitrary code path
# exists for the client to reach.
# --------------------------------------------------------------------- #
import ast
import operator

_ALLOWED_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.USub: operator.neg,
}


def _safe_eval(node):
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_OPS:
        return _ALLOWED_OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_OPS:
        return _ALLOWED_OPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError("Unsupported expression")


@app.route("/calculate")
def calculate():
    expr = request.args.get("expr", "0")
    try:
        tree = ast.parse(expr, mode="eval")
        result = _safe_eval(tree)
    except (ValueError, SyntaxError, ZeroDivisionError, TypeError):
        abort(400, description="Invalid expression")
    return {"result": result}


# --------------------------------------------------------------------- #
# FIX-07 (was VULN-06): Insecure Deserialization
# pickle.loads() is replaced with json.loads(). JSON cannot embed
# executable code, so a malicious payload can no longer trigger
# arbitrary code execution during deserialization.
# --------------------------------------------------------------------- #
@app.route("/load-session", methods=["POST"])
def load_session():
    try:
        session_obj = json.loads(request.get_data())
    except json.JSONDecodeError:
        abort(400, description="Invalid JSON payload")
    return {"loaded": session_obj}


# --------------------------------------------------------------------- #
# FIX-08 (was VULN-07): Weak hashing for passwords
# MD5 is replaced with werkzeug's generate_password_hash, which uses a
# salted, adaptive algorithm (PBKDF2/scrypt) suited for password storage.
# --------------------------------------------------------------------- #
def hash_password(password):
    return generate_password_hash(password)


@app.route("/register", methods=["POST"])
def register():
    password = request.form.get("password", "")
    hashed = hash_password(password)
    return {"stored_hash": hashed}


# --------------------------------------------------------------------- #
# FIX-09 (was VULN-08): Insecure randomness for a security-sensitive token
# The `random` module is replaced with `secrets`, which is designed for
# cryptographic and security-sensitive use.
# --------------------------------------------------------------------- #
@app.route("/reset-token")
def generate_reset_token():
    token = "".join(secrets.choice("0123456789") for _ in range(6))
    return {"reset_token": token}


# --------------------------------------------------------------------- #
# FIX-10 (was VULN-09): SSRF-prone request + disabled TLS verification
# The target URL is restricted to https:// and validated against a host
# allowlist before the request is made, certificate verification is
# re-enabled, and a timeout is set.
# --------------------------------------------------------------------- #
ALLOWED_FETCH_HOSTS = {"api.example.com", "data.example.com"}


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FETCH_HOSTS:
        abort(400, description="URL not allowed")
    response = requests.get(url, verify=True, timeout=5)
    return {"content_length": len(response.content)}


# --------------------------------------------------------------------- #
# FIX-11 (was VULN-10): Reflected XSS via unescaped template rendering
# render_template_string with raw f-string interpolation is replaced
# with escape(), so any HTML/JS in the input is rendered inert.
# --------------------------------------------------------------------- #
@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return f"<h1>Hello, {escape(name)}!</h1>"


# --------------------------------------------------------------------- #
# FIX-12 (was VULN-11): Path traversal in file download
# The filename is sanitized with secure_filename and the resolved path
# is checked to ensure it still lives inside the uploads directory
# before the file is opened.
# --------------------------------------------------------------------- #
UPLOAD_DIR = os.path.realpath("/app/uploads")


@app.route("/download")
def download_file():
    filename = secure_filename(request.args.get("file", ""))
    if not filename:
        abort(400, description="Invalid filename")
    filepath = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
    if not filepath.startswith(UPLOAD_DIR + os.sep):
        abort(403, description="Access denied")
    if not os.path.isfile(filepath):
        abort(404)
    with open(filepath, "rb") as f:
        return f.read()


# --------------------------------------------------------------------- #
# FIX-13 (was VULN-12): Debug mode enabled + bind to all interfaces
# Debug mode is off by default and only enabled via an explicit env
# var for local development. The bind host defaults to localhost
# instead of 0.0.0.0.
# --------------------------------------------------------------------- #
if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    bind_host = os.environ.get("FLASK_HOST", "127.0.0.1")
    app.run(debug=debug_mode, host=bind_host)
