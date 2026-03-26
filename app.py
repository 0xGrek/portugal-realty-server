"""Portugal Realty — cloud backend for shared favorites/notes.
Deployed on Render.com free tier.
"""
import json
import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, redirect, request, send_from_directory, session

app = Flask(__name__, static_folder="static")
app.secret_key = os.getenv("SECRET_KEY", "pr_secret_2026_render")

DB_PATH = Path(__file__).parent / "data" / "shared.db"
DB_PATH.parent.mkdir(exist_ok=True)

PASSWORD = os.getenv("APP_PASSWORD", "realty2026portugalrealty2026portugalrealty2026portugal")


def _get_conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS shared_favorites (
            listing_id TEXT PRIMARY KEY,
            category TEXT NOT NULL DEFAULT 'fav',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS shared_notes (
            listing_id TEXT PRIMARY KEY,
            note TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check session OR X-Password header
        if session.get("authed"):
            return f(*args, **kwargs)
        pw = request.headers.get("X-Password", "")
        if pw == PASSWORD:
            return f(*args, **kwargs)
        return jsonify({"error": "unauthorized"}), 401
    return decorated


# --- Auth ---

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    if data.get("password") == PASSWORD:
        session["authed"] = True
        session.permanent = True
        return jsonify({"ok": True})
    return jsonify({"error": "wrong password"}), 403


# --- Shared state API ---

@app.route("/api/state")
@login_required
def get_state():
    conn = _get_conn()
    favs, maybe, blocked, contacted = {}, {}, {}, {}
    for row in conn.execute("SELECT listing_id, category FROM shared_favorites"):
        if row["category"] == "fav":
            favs[row["listing_id"]] = True
        elif row["category"] == "maybe":
            maybe[row["listing_id"]] = True
        elif row["category"] == "blocked":
            blocked[row["listing_id"]] = True
        elif row["category"] == "contacted":
            contacted[row["listing_id"]] = True
    notes = {}
    for row in conn.execute("SELECT listing_id, note FROM shared_notes"):
        notes[row["listing_id"]] = row["note"]
    conn.close()
    return jsonify({"favs": favs, "maybe": maybe, "blocked": blocked, "contacted": contacted, "notes": notes})


@app.route("/api/fav/<lid>", methods=["POST", "DELETE"])
@login_required
def toggle_fav(lid):
    conn = _get_conn()
    conn.execute("DELETE FROM shared_favorites WHERE listing_id = ?", (lid,))
    if request.method == "POST":
        conn.execute("INSERT INTO shared_favorites (listing_id, category) VALUES (?, 'fav')", (lid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/maybe/<lid>", methods=["POST", "DELETE"])
@login_required
def toggle_maybe(lid):
    conn = _get_conn()
    conn.execute("DELETE FROM shared_favorites WHERE listing_id = ?", (lid,))
    if request.method == "POST":
        conn.execute("INSERT INTO shared_favorites (listing_id, category) VALUES (?, 'maybe')", (lid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/contacted/<lid>", methods=["POST", "DELETE"])
@login_required
def toggle_contacted(lid):
    conn = _get_conn()
    conn.execute("DELETE FROM shared_favorites WHERE listing_id = ?", (lid,))
    if request.method == "POST":
        conn.execute("INSERT INTO shared_favorites (listing_id, category) VALUES (?, 'contacted')", (lid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/block/<lid>", methods=["POST", "DELETE"])
@login_required
def toggle_block(lid):
    conn = _get_conn()
    conn.execute("DELETE FROM shared_favorites WHERE listing_id = ?", (lid,))
    if request.method == "POST":
        conn.execute("INSERT INTO shared_favorites (listing_id, category) VALUES (?, 'blocked')", (lid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/note/<lid>", methods=["POST", "DELETE"])
@login_required
def save_note(lid):
    conn = _get_conn()
    if request.method == "POST":
        data = request.get_json() or {}
        note = data.get("note", "").strip()
        if note:
            conn.execute("INSERT OR REPLACE INTO shared_notes (listing_id, note) VALUES (?, ?)", (lid, note))
        else:
            conn.execute("DELETE FROM shared_notes WHERE listing_id = ?", (lid,))
    else:
        conn.execute("DELETE FROM shared_notes WHERE listing_id = ?", (lid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# --- Static files ---

@app.route("/")
def index():
    if not session.get("authed"):
        return send_from_directory("static", "login.html")
    return send_from_directory("static", "index.html")


_init_db()

if __name__ == "__main__":
    from datetime import timedelta
    app.permanent_session_lifetime = timedelta(days=30)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5555)))
