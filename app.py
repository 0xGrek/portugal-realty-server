"""Portugal Realty — cloud backend for shared favorites/notes.
Uses Neon PostgreSQL — data persists across Render deploys.
"""
import hmac
import os
from contextlib import contextmanager
from functools import wraps

import psycopg2
from flask import Flask, jsonify, redirect, request, send_from_directory, session

app = Flask(__name__, static_folder="static")
app.secret_key = os.getenv("SECRET_KEY")

NEON_URL = os.getenv("NEON_DATABASE_URL")
PASSWORD = os.getenv("APP_PASSWORD")
if not app.secret_key or not NEON_URL or not PASSWORD:
    raise RuntimeError("Missing required env vars: SECRET_KEY, NEON_DATABASE_URL, APP_PASSWORD")


@contextmanager
def _get_conn():
    """Context manager — guarantees connection close even on exception."""
    conn = psycopg2.connect(NEON_URL)
    try:
        yield conn
    finally:
        conn.close()


def _init_schema():
    """Bootstrap schema — idempotent. UNIQUE(listing_id) prevents duplicate rows."""
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS shared_favorites (
                listing_id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS shared_notes (
                listing_id TEXT PRIMARY KEY,
                note TEXT NOT NULL,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        # Backfill UNIQUE constraint if old schema lacks it (safe no-op when already present).
        cur.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conname = 'shared_favorites_listing_id_key'
                ) THEN
                    BEGIN
                        ALTER TABLE shared_favorites
                        ADD CONSTRAINT shared_favorites_listing_id_key UNIQUE (listing_id);
                    EXCEPTION WHEN duplicate_table OR duplicate_object OR invalid_table_definition THEN
                        NULL;
                    END;
                END IF;
            END$$;
        """)
        conn.commit()


_init_schema()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("authed"):
            return f(*args, **kwargs)
        pw = request.headers.get("X-Password", "")
        if hmac.compare_digest(pw, PASSWORD):
            return f(*args, **kwargs)
        return jsonify({"error": "unauthorized"}), 401
    return decorated


# --- Auth ---

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    submitted = data.get("password") or ""
    if hmac.compare_digest(submitted, PASSWORD):
        session["authed"] = True
        session.permanent = True
        return jsonify({"ok": True})
    return jsonify({"error": "wrong password"}), 403


# --- Shared state API ---

@app.route("/api/state")
@login_required
def get_state():
    conn = _get_conn()
    cur = conn.cursor()
    favs, maybe, blocked, contacted = {}, {}, {}, {}
    cur.execute("SELECT listing_id, category FROM shared_favorites")
    for row in cur.fetchall():
        lid, cat = row
        if cat == "fav":
            favs[lid] = True
        elif cat == "maybe":
            maybe[lid] = True
        elif cat == "blocked":
            blocked[lid] = True
        elif cat == "contacted":
            contacted[lid] = True

    notes = {}
    cur.execute("SELECT listing_id, note FROM shared_notes")
    for row in cur.fetchall():
        notes[row[0]] = row[1]

    conn.close()
    return jsonify({"favs": favs, "maybe": maybe, "blocked": blocked, "contacted": contacted, "notes": notes})


def _set_category(listing_id, category):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM shared_favorites WHERE listing_id = %s", (listing_id,))
    if request.method == "POST":
        cur.execute("INSERT INTO shared_favorites (listing_id, category) VALUES (%s, %s)", (listing_id, category))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/fav/<lid>", methods=["POST", "DELETE"])
@login_required
def toggle_fav(lid):
    return _set_category(lid, "fav")


@app.route("/api/contacted/<lid>", methods=["POST", "DELETE"])
@login_required
def toggle_contacted(lid):
    return _set_category(lid, "contacted")


@app.route("/api/maybe/<lid>", methods=["POST", "DELETE"])
@login_required
def toggle_maybe(lid):
    return _set_category(lid, "maybe")


@app.route("/api/block/<lid>", methods=["POST", "DELETE"])
@login_required
def toggle_block(lid):
    return _set_category(lid, "blocked")


@app.route("/api/note/<lid>", methods=["POST", "DELETE"])
@login_required
def save_note(lid):
    conn = _get_conn()
    cur = conn.cursor()
    if request.method == "POST":
        data = request.get_json() or {}
        note = data.get("note", "").strip()
        if note:
            cur.execute(
                "INSERT INTO shared_notes (listing_id, note) VALUES (%s, %s) "
                "ON CONFLICT (listing_id) DO UPDATE SET note = %s",
                (lid, note, note),
            )
        else:
            cur.execute("DELETE FROM shared_notes WHERE listing_id = %s", (lid,))
    else:
        cur.execute("DELETE FROM shared_notes WHERE listing_id = %s", (lid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# --- Static files ---

@app.route("/")
def index():
    if not session.get("authed"):
        return send_from_directory("static", "login.html")
    return send_from_directory("static", "index.html")


if __name__ == "__main__":
    from datetime import timedelta
    app.permanent_session_lifetime = timedelta(days=30)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5555)))
