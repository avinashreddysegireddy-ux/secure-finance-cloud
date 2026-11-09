"""
Secure Finance Cloud - simple base version
Features:
  * User registration / login (PBKDF2 password hashing, account lockout)
  * Financial transactions encrypted at rest (Fernet / AES-128-CBC + HMAC)
  * CSRF protection, secure cookies, security headers
  * Audit log of every sensitive action
  * Roles: first registered user = admin (can view audit log)
Run:  pip install -r requirements.txt && python app.py
"""
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps

from cryptography.fernet import Fernet
from flask import (Flask, abort, flash, g, redirect, render_template_string,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "finance.db")
MAX_FAILED = 5
LOCK_MINUTES = 10


# ----------------------------------------------------------------- key setup
def load_secret(env_name, filename, generator):
    """Read secret from env var, else from a local file (created on first run)."""
    val = os.environ.get(env_name)
    if val:
        return val.encode()
    path = os.path.join(BASE_DIR, filename)
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(generator())
        os.chmod(path, 0o600)
    with open(path, "rb") as f:
        return f.read().strip()


app = Flask(__name__)
app.secret_key = load_secret("SFC_SECRET_KEY", ".flask_secret",
                             lambda: secrets.token_hex(32).encode())
fernet = Fernet(load_secret("SFC_FERNET_KEY", ".fernet_key", Fernet.generate_key))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SFC_HTTPS") == "1",  # set to 1 behind HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=20),
)


# ------------------------------------------------------------------ database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT
    );
    CREATE TABLE IF NOT EXISTS transactions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        kind TEXT NOT NULL CHECK(kind IN ('income','expense')),
        amount_enc BLOB NOT NULL,
        note_enc BLOB NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        username TEXT,
        action TEXT NOT NULL,
        ip TEXT
    );
    """)
    db.commit()
    db.close()


def audit(action, username=None):
    get_db().execute(
        "INSERT INTO audit_log(ts, username, action, ip) VALUES (?,?,?,?)",
        (now().isoformat(timespec="seconds"),
         username or session.get("username"), action, request.remote_addr))
    get_db().commit()


def now():
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------ security
def enc(text):
    return fernet.encrypt(text.encode())


def dec(blob):
    return fernet.decrypt(blob).decode()


@app.before_request
def csrf_protect():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("csrf", ""), session["csrf"]):
            abort(400, "Invalid CSRF token")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'")
    return resp


def login_required(role=None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if "uid" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


def strong_password(pw):
    return (len(pw) >= 10 and re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw)
            and re.search(r"\d", pw) and re.search(r"[^\w\s]", pw))


# ----------------------------------------------------------------- templates
BASE = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Finance Cloud</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:820px;margin:0 auto;padding:1rem;color:#1b2430}
 nav{display:flex;gap:1rem;align-items:center;border-bottom:1px solid #ccd;padding:.6rem 0;margin-bottom:1rem}
 nav b{margin-right:auto;color:#0b5fff}
 input,select,button{padding:.5rem;margin:.2rem 0;font-size:1rem}
 input,select{width:100%;box-sizing:border-box}
 button{background:#0b5fff;color:#fff;border:0;border-radius:6px;cursor:pointer}
 table{width:100%;border-collapse:collapse} td,th{border-bottom:1px solid #e3e6ee;padding:.4rem;text-align:left}
 .card{background:#f5f7fb;padding:1rem;border-radius:8px;margin-bottom:1rem}
 .income{color:#0a7d33}.expense{color:#c0262d}.flash{background:#fff3cd;padding:.5rem;border-radius:6px;margin-bottom:.5rem}
 form.inline{display:inline}
</style></head><body>
<nav><b>🔒 Secure Finance Cloud</b>
{% if session.uid %}<span>{{ session.username }} ({{ session.role }})</span>
<a href="{{ url_for('dashboard') }}">Dashboard</a>
{% if session.role=='admin' %}<a href="{{ url_for('audit_view') }}">Audit log</a>{% endif %}
<form class="inline" method="post" action="{{ url_for('logout') }}">
<input type="hidden" name="csrf" value="{{ session.csrf }}"><button>Logout</button></form>
{% else %}<a href="{{ url_for('login') }}">Login</a><a href="{{ url_for('register') }}">Register</a>{% endif %}
</nav>
{% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}
{% block body %}{% endblock %}
</body></html>
"""

AUTH = """{% extends base %}{% block body %}
<div class="card"><h2>{{ title }}</h2>
<form method="post"><input type="hidden" name="csrf" value="{{ session.csrf }}">
<label>Username</label><input name="username" required maxlength="32" autocomplete="username">
<label>Password</label><input name="password" type="password" required autocomplete="current-password">
{% if title=='Register' %}<small>Min 10 chars with upper, lower, digit and symbol.</small>{% endif %}
<button>{{ title }}</button></form></div>{% endblock %}"""

DASH = """{% extends base %}{% block body %}
<div class="card"><h2>Balance: ₹{{ '%.2f'|format(balance) }}</h2>
<small>Income ₹{{ '%.2f'|format(income) }} · Expenses ₹{{ '%.2f'|format(expense) }}</small></div>
<div class="card"><h3>Add transaction</h3>
<form method="post" action="{{ url_for('add_tx') }}"><input type="hidden" name="csrf" value="{{ session.csrf }}">
<select name="kind"><option value="income">Income</option><option value="expense">Expense</option></select>
<input name="amount" type="number" step="0.01" min="0.01" max="999999999" placeholder="Amount" required>
<input name="note" maxlength="120" placeholder="Description" required>
<button>Save (encrypted)</button></form></div>
<h3>Transactions</h3>
<table><tr><th>Date</th><th>Description</th><th>Amount</th><th></th></tr>
{% for t in txs %}<tr><td>{{ t.date }}</td><td>{{ t.note }}</td>
<td class="{{ t.kind }}">{{ '-' if t.kind=='expense' else '+' }}₹{{ t.amount }}</td>
<td><form class="inline" method="post" action="{{ url_for('delete_tx', tx_id=t.id) }}">
<input type="hidden" name="csrf" value="{{ session.csrf }}"><button style="background:#c0262d">Delete</button></form></td></tr>
{% else %}<tr><td colspan="4">No transactions yet.</td></tr>{% endfor %}</table>{% endblock %}"""

AUDIT = """{% extends base %}{% block body %}<h2>Audit log (latest 200)</h2>
<table><tr><th>Time (UTC)</th><th>User</th><th>Action</th><th>IP</th></tr>
{% for r in rows %}<tr><td>{{ r.ts }}</td><td>{{ r.username or '-' }}</td><td>{{ r.action }}</td><td>{{ r.ip }}</td></tr>{% endfor %}
</table>{% endblock %}"""


def render(tpl, **ctx):
    # Jinja autoescape is enabled for render_template_string -> XSS-safe
    from jinja2 import DictLoader
    app.jinja_loader = DictLoader({"base.html": BASE})
    return render_template_string(tpl, base="base.html", **ctx)


# -------------------------------------------------------------------- routes
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "uid" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            flash("Username must be 3-32 chars (letters, digits, _ . -).")
        elif not strong_password(password):
            flash("Password too weak.")
        else:
            db = get_db()
            role = "admin" if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0 else "user"
            try:
                db.execute("INSERT INTO users(username,password_hash,role) VALUES (?,?,?)",
                           (username, generate_password_hash(password), role))
                db.commit()
                audit("register", username)
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username already taken.")
    return render(AUTH, title="Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if u and u["locked_until"] and datetime.fromisoformat(u["locked_until"]) > now():
            audit("login_blocked_locked", username)
            flash("Account temporarily locked. Try again later.")
        elif u and check_password_hash(u["password_hash"], password):
            db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (u["id"],))
            db.commit()
            session.clear()
            session.permanent = True
            session.update(uid=u["id"], username=u["username"], role=u["role"],
                           csrf=secrets.token_hex(16))
            audit("login_success")
            return redirect(url_for("dashboard"))
        else:
            if u:
                fails = u["failed_attempts"] + 1
                lock = (now() + timedelta(minutes=LOCK_MINUTES)).isoformat() if fails >= MAX_FAILED else None
                db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                           (0 if lock else fails, lock, u["id"]))
                db.commit()
            audit("login_failed", username)
            flash("Invalid credentials.")  # generic message: no user enumeration
    return render(AUTH, title="Login")


@app.route("/logout", methods=["POST"])
@login_required()
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required()
def dashboard():
    rows = get_db().execute(
        "SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC", (session["uid"],)).fetchall()
    txs, income, expense = [], Decimal(0), Decimal(0)
    for r in rows:
        amt = Decimal(dec(r["amount_enc"]))
        income += amt if r["kind"] == "income" else 0
        expense += amt if r["kind"] == "expense" else 0
        txs.append(dict(id=r["id"], kind=r["kind"], amount=f"{amt:.2f}",
                        note=dec(r["note_enc"]), date=r["created_at"][:10]))
    return render(DASH, txs=txs, income=income, expense=expense, balance=income - expense)


@app.route("/transactions/add", methods=["POST"])
@login_required()
def add_tx():
    kind = request.form.get("kind")
    note = request.form.get("note", "").strip()[:120]
    try:
        amount = Decimal(request.form.get("amount", "")).quantize(Decimal("0.01"))
        assert 0 < amount < Decimal("1000000000") and kind in ("income", "expense") and note
    except (InvalidOperation, AssertionError):
        flash("Invalid transaction data.")
        return redirect(url_for("dashboard"))
    db = get_db()
    db.execute("INSERT INTO transactions(user_id,kind,amount_enc,note_enc,created_at) VALUES (?,?,?,?,?)",
               (session["uid"], kind, enc(str(amount)), enc(note), now().isoformat(timespec="seconds")))
    db.commit()
    audit(f"add_{kind}")
    return redirect(url_for("dashboard"))


@app.route("/transactions/<int:tx_id>/delete", methods=["POST"])
@login_required()
def delete_tx(tx_id):
    db = get_db()
    # user_id check prevents accessing other users' records (IDOR protection)
    cur = db.execute("DELETE FROM transactions WHERE id=? AND user_id=?", (tx_id, session["uid"]))
    db.commit()
    if cur.rowcount:
        audit(f"delete_tx_{tx_id}")
    return redirect(url_for("dashboard"))


@app.route("/admin/audit")
@login_required(role="admin")
def audit_view():
    rows = get_db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
    return render(AUDIT, rows=rows)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
