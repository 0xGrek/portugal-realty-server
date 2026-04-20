"""Portugal Realty — cloud backend with multi-user authentication.
Per-user favorites, notes, and removed listings. Admin creates users.
Uses Neon PostgreSQL — data persists across Render deploys.
"""
import hmac
import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import timedelta
from functools import wraps

import bcrypt
import psycopg2
from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    request,
    send_from_directory,
    session,
    url_for,
)

app = Flask(__name__, static_folder="static")
app.secret_key = os.getenv("SECRET_KEY")

NEON_URL = os.getenv("NEON_DATABASE_URL")
LEGACY_PASSWORD = os.getenv("APP_PASSWORD")  # kept for 1-release backward compat
ADMIN_PASSWORD = os.getenv("APP_ADMIN_PASSWORD")  # used for seeding admin user

if not app.secret_key or not NEON_URL:
    raise RuntimeError("Missing required env vars: SECRET_KEY, NEON_DATABASE_URL")

# Secure session cookies (HTTPS on Render).
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)


# --- DB helpers ---

@contextmanager
def _get_conn():
    """Context manager — guarantees connection close even on exception."""
    conn = psycopg2.connect(NEON_URL)
    try:
        yield conn
    finally:
        conn.close()


def _hash_password(plain: str) -> str:
    """bcrypt hash (rounds=12). Returns utf-8 string for TEXT column."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def _check_password(plain: str, stored_hash: str) -> bool:
    """Constant-time bcrypt check. Safe against timing attacks by design."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --- Schema migration ---

def _init_schema():
    """Bootstrap schema — idempotent. Create new user tables, keep legacy shared_* intact."""
    with _get_conn() as conn:
        cur = conn.cursor()

        # Legacy tables (kept for rollback, NOT dropped).
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

        # New multi-user tables.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                last_login TIMESTAMPTZ
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_favorites (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                listing_id TEXT NOT NULL,
                category TEXT DEFAULT 'saved',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(user_id, listing_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_notes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                listing_id TEXT NOT NULL,
                note TEXT,
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(user_id, listing_id)
            )
        """)
        conn.commit()


def _seed_admin():
    """Create admin user 'serhii' if users table empty. Migrate legacy shared_* to serhii."""
    if not ADMIN_PASSWORD:
        print("[seed] APP_ADMIN_PASSWORD not set — skipping admin seed")
        return

    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        count = cur.fetchone()[0]
        if count > 0:
            return

        # Create admin user.
        pw_hash = _hash_password(ADMIN_PASSWORD)
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, TRUE) RETURNING id",
            ("serhii", pw_hash),
        )
        serhii_id = cur.fetchone()[0]
        print(f"[seed] Admin user 'serhii' created (id={serhii_id})")

        # Migrate shared_favorites → user_favorites for serhii.
        cur.execute("""
            INSERT INTO user_favorites (user_id, listing_id, category, created_at)
            SELECT %s, listing_id, category, created_at FROM shared_favorites
            ON CONFLICT (user_id, listing_id) DO NOTHING
        """, (serhii_id,))
        favs_migrated = cur.rowcount

        # Migrate shared_notes → user_notes for serhii.
        cur.execute("""
            INSERT INTO user_notes (user_id, listing_id, note, updated_at)
            SELECT %s, listing_id, note, updated_at FROM shared_notes
            ON CONFLICT (user_id, listing_id) DO NOTHING
        """, (serhii_id,))
        notes_migrated = cur.rowcount

        conn.commit()
        print(f"[seed] Migrated {favs_migrated} favorites and {notes_migrated} notes to serhii")


_init_schema()
_seed_admin()


# --- Rate limiter (in-memory, 5 login attempts / 5 min / IP) ---

_login_attempts: dict[str, deque] = defaultdict(deque)
_RATE_WINDOW_SEC = 300
_RATE_MAX = 5


def _rate_limited(ip: str) -> bool:
    """Check if IP is rate-limited. Prunes old entries on each call."""
    now = time.time()
    dq = _login_attempts[ip]
    while dq and now - dq[0] > _RATE_WINDOW_SEC:
        dq.popleft()
    return len(dq) >= _RATE_MAX


def _record_attempt(ip: str) -> None:
    _login_attempts[ip].append(time.time())


# --- CSRF token ---

def _get_csrf_token() -> str:
    """Returns CSRF token for current session. Generates if missing."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def _check_csrf() -> bool:
    """Verify CSRF token from header or JSON body matches session token."""
    token = request.headers.get("X-CSRF-Token")
    if not token:
        data = request.get_json(silent=True) or {}
        token = data.get("csrf_token", "")
    stored = session.get("csrf_token", "")
    if not stored or not token:
        return False
    return hmac.compare_digest(stored, token)


# --- Decorators ---

def login_required(f):
    """Reject if session has no user_id. Also accepts legacy X-Password for 1-release compat."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("user_id"):
            return f(*args, **kwargs)
        # Legacy fallback: X-Password header → map to admin user.
        if LEGACY_PASSWORD:
            pw = request.headers.get("X-Password", "")
            if pw and hmac.compare_digest(pw, LEGACY_PASSWORD):
                with _get_conn() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id FROM users WHERE username = 'serhii'")
                    row = cur.fetchone()
                    if row:
                        session["user_id"] = row[0]
                        session["username"] = "serhii"
                        session["is_admin"] = True
                        return f(*args, **kwargs)
        return jsonify({"error": "unauthorized"}), 401
    return decorated


def admin_required(f):
    """Reject if not admin. 403 — not 401 — because user is authed."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "unauthorized"}), 401
        if not session.get("is_admin"):
            return jsonify({"error": "forbidden"}), 403
        return f(*args, **kwargs)
    return decorated


def csrf_required(f):
    """Reject POST/DELETE/PUT without valid CSRF token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "DELETE", "PUT", "PATCH"):
            # Allow legacy X-Password as alternative to CSRF (backward compat).
            legacy_ok = False
            if LEGACY_PASSWORD:
                pw = request.headers.get("X-Password", "")
                if pw and hmac.compare_digest(pw, LEGACY_PASSWORD):
                    legacy_ok = True
            if not legacy_ok and not _check_csrf():
                return jsonify({"error": "csrf_invalid"}), 403
        return f(*args, **kwargs)
    return decorated


# --- Auth endpoints ---

@app.route("/login", methods=["GET"])
def login_page():
    if session.get("user_id"):
        return redirect(url_for("index"))
    return send_from_directory("static", "login.html")


@app.route("/api/login", methods=["POST"])
def login():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if _rate_limited(ip):
        return jsonify({"error": "Too many attempts. Try again in 5 minutes."}), 429

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    # Legacy mode: old clients may send only {password}. Map to 'serhii'.
    if not username and password and LEGACY_PASSWORD and hmac.compare_digest(password, LEGACY_PASSWORD):
        username = "serhii"
        password = ADMIN_PASSWORD or password

    if not username or not password:
        _record_attempt(ip)
        return jsonify({"error": "Invalid credentials"}), 401

    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password_hash, is_admin FROM users WHERE username = %s",
            (username,),
        )
        row = cur.fetchone()

        if not row or not _check_password(password, row[2]):
            _record_attempt(ip)
            # Identical error message — don't leak "user not found" vs "wrong password".
            return jsonify({"error": "Invalid credentials"}), 401

        cur.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (row[0],))
        conn.commit()

    session.clear()
    session["user_id"] = row[0]
    session["username"] = row[1]
    session["is_admin"] = bool(row[3])
    session.permanent = True
    _get_csrf_token()  # generate CSRF token post-login

    return jsonify({
        "ok": True,
        "username": row[1],
        "is_admin": bool(row[3]),
        "csrf_token": session["csrf_token"],
    })


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/api/logout", methods=["POST"])
@csrf_required
def api_logout():
    """JSON-friendly logout. CSRF-protected; frontend redirects after ok:true."""
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
@login_required
def me():
    return jsonify({
        "user_id": session["user_id"],
        "username": session.get("username"),
        "is_admin": session.get("is_admin", False),
        "csrf_token": _get_csrf_token(),
    })


# --- Admin endpoints ---

@app.route("/admin", methods=["GET"])
@admin_required
def admin_page():
    return send_from_directory("static", "admin.html")


@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, is_admin, created_at, last_login "
            "FROM users ORDER BY created_at ASC"
        )
        users = [
            {
                "id": r[0],
                "username": r[1],
                "is_admin": r[2],
                "created_at": r[3].isoformat() if r[3] else None,
                "last_login": r[4].isoformat() if r[4] else None,
            }
            for r in cur.fetchall()
        ]
    return jsonify({"users": users})


@app.route("/api/admin/users", methods=["POST"])
@admin_required
@csrf_required
def admin_create_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    is_admin = bool(data.get("is_admin", False))

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400
    if len(username) > 64 or not username.replace("_", "").replace("-", "").isalnum():
        return jsonify({"error": "username: alphanumeric + _ - only, max 64 chars"}), 400

    with _get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash, is_admin) "
                "VALUES (%s, %s, %s) RETURNING id",
                (username, _hash_password(password), is_admin),
            )
            user_id = cur.fetchone()[0]
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            return jsonify({"error": "username already exists"}), 409

    return jsonify({"ok": True, "id": user_id, "username": username})


@app.route("/api/admin/users/<int:user_id>/password", methods=["POST"])
@admin_required
@csrf_required
def admin_reset_password(user_id):
    data = request.get_json(silent=True) or {}
    new_password = data.get("password") or ""
    if len(new_password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (_hash_password(new_password), user_id),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "user not found"}), 404
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
@csrf_required
def admin_delete_user(user_id):
    # Protect against deleting yourself — avoid locking out all admins.
    if user_id == session.get("user_id"):
        return jsonify({"error": "cannot delete self"}), 400

    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        if cur.rowcount == 0:
            return jsonify({"error": "user not found"}), 404
        conn.commit()
    return jsonify({"ok": True})


# --- Per-user state API ---

@app.route("/api/state")
@login_required
def get_state():
    """Returns current user's favs/maybe/blocked/contacted/notes + saved category."""
    user_id = session["user_id"]
    favs, maybe, blocked, contacted, saved = {}, {}, {}, {}, {}
    notes = {}

    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT listing_id, category FROM user_favorites WHERE user_id = %s",
            (user_id,),
        )
        for lid, cat in cur.fetchall():
            if cat == "fav":
                favs[lid] = True
            elif cat == "maybe":
                maybe[lid] = True
            elif cat == "blocked":
                blocked[lid] = True
            elif cat == "contacted":
                contacted[lid] = True
            elif cat == "saved":
                saved[lid] = True

        cur.execute(
            "SELECT listing_id, note FROM user_notes WHERE user_id = %s",
            (user_id,),
        )
        for lid, note in cur.fetchall():
            notes[lid] = note

    return jsonify({
        "favs": favs,
        "maybe": maybe,
        "blocked": blocked,
        "contacted": contacted,
        "saved": saved,
        "notes": notes,
    })


def _set_user_category(listing_id, category):
    """Toggle category for current user. POST = set, DELETE = remove."""
    user_id = session["user_id"]
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM user_favorites WHERE user_id = %s AND listing_id = %s",
            (user_id, listing_id),
        )
        if request.method == "POST":
            cur.execute(
                "INSERT INTO user_favorites (user_id, listing_id, category) "
                "VALUES (%s, %s, %s) "
                "ON CONFLICT (user_id, listing_id) DO UPDATE SET category = EXCLUDED.category",
                (user_id, listing_id, category),
            )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/favorites", methods=["GET"])
@login_required
def list_favorites():
    user_id = session["user_id"]
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT listing_id, category, created_at FROM user_favorites "
            "WHERE user_id = %s ORDER BY created_at DESC",
            (user_id,),
        )
        items = [
            {"listing_id": r[0], "category": r[1], "created_at": r[2].isoformat() if r[2] else None}
            for r in cur.fetchall()
        ]
    return jsonify({"favorites": items})


@app.route("/api/favorites", methods=["POST"])
@login_required
@csrf_required
def add_favorite():
    data = request.get_json(silent=True) or {}
    listing_id = (data.get("listing_id") or "").strip()
    category = (data.get("category") or "saved").strip()
    if not listing_id:
        return jsonify({"error": "listing_id required"}), 400
    if category not in ("saved", "fav", "maybe", "blocked", "contacted", "removed"):
        return jsonify({"error": "invalid category"}), 400

    user_id = session["user_id"]
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO user_favorites (user_id, listing_id, category) "
            "VALUES (%s, %s, %s) "
            "ON CONFLICT (user_id, listing_id) DO UPDATE SET category = EXCLUDED.category",
            (user_id, listing_id, category),
        )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/favorites/<lid>", methods=["DELETE"])
@login_required
@csrf_required
def delete_favorite(lid):
    user_id = session["user_id"]
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM user_favorites WHERE user_id = %s AND listing_id = %s",
            (user_id, lid),
        )
        conn.commit()
    return jsonify({"ok": True})


# Legacy category endpoints (kept for dashboard frontend compat).

@app.route("/api/fav/<lid>", methods=["POST", "DELETE"])
@login_required
@csrf_required
def toggle_fav(lid):
    return _set_user_category(lid, "fav")


@app.route("/api/contacted/<lid>", methods=["POST", "DELETE"])
@login_required
@csrf_required
def toggle_contacted(lid):
    return _set_user_category(lid, "contacted")


@app.route("/api/maybe/<lid>", methods=["POST", "DELETE"])
@login_required
@csrf_required
def toggle_maybe(lid):
    return _set_user_category(lid, "maybe")


@app.route("/api/block/<lid>", methods=["POST", "DELETE"])
@login_required
@csrf_required
def toggle_block(lid):
    return _set_user_category(lid, "blocked")


# --- Notes API ---

@app.route("/api/notes", methods=["GET"])
@login_required
def list_notes():
    user_id = session["user_id"]
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT listing_id, note, updated_at FROM user_notes WHERE user_id = %s",
            (user_id,),
        )
        items = [
            {"listing_id": r[0], "note": r[1], "updated_at": r[2].isoformat() if r[2] else None}
            for r in cur.fetchall()
        ]
    return jsonify({"notes": items})


@app.route("/api/notes", methods=["POST"])
@login_required
@csrf_required
def upsert_note():
    data = request.get_json(silent=True) or {}
    listing_id = (data.get("listing_id") or "").strip()
    note = (data.get("note") or "").strip()
    if not listing_id:
        return jsonify({"error": "listing_id required"}), 400

    user_id = session["user_id"]
    with _get_conn() as conn:
        cur = conn.cursor()
        if note:
            cur.execute(
                "INSERT INTO user_notes (user_id, listing_id, note, updated_at) "
                "VALUES (%s, %s, %s, NOW()) "
                "ON CONFLICT (user_id, listing_id) DO UPDATE "
                "SET note = EXCLUDED.note, updated_at = NOW()",
                (user_id, listing_id, note),
            )
        else:
            cur.execute(
                "DELETE FROM user_notes WHERE user_id = %s AND listing_id = %s",
                (user_id, listing_id),
            )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/notes/<lid>", methods=["DELETE"])
@login_required
@csrf_required
def delete_note(lid):
    user_id = session["user_id"]
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM user_notes WHERE user_id = %s AND listing_id = %s",
            (user_id, lid),
        )
        conn.commit()
    return jsonify({"ok": True})


# Legacy note endpoint (kept for backward compat).

@app.route("/api/note/<lid>", methods=["POST", "DELETE"])
@login_required
@csrf_required
def save_note_legacy(lid):
    user_id = session["user_id"]
    with _get_conn() as conn:
        cur = conn.cursor()
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            note = (data.get("note") or "").strip()
            if note:
                cur.execute(
                    "INSERT INTO user_notes (user_id, listing_id, note, updated_at) "
                    "VALUES (%s, %s, %s, NOW()) "
                    "ON CONFLICT (user_id, listing_id) DO UPDATE "
                    "SET note = EXCLUDED.note, updated_at = NOW()",
                    (user_id, lid, note),
                )
            else:
                cur.execute(
                    "DELETE FROM user_notes WHERE user_id = %s AND listing_id = %s",
                    (user_id, lid),
                )
        else:
            cur.execute(
                "DELETE FROM user_notes WHERE user_id = %s AND listing_id = %s",
                (user_id, lid),
            )
        conn.commit()
    return jsonify({"ok": True})


# --- Sync endpoint (copy current user's favorites to target user) ---

@app.route("/api/sync", methods=["POST"])
@login_required
@csrf_required
def sync_to_user():
    data = request.get_json(silent=True) or {}
    target_username = (data.get("target_username") or "").strip()
    if not target_username:
        return jsonify({"error": "target_username required"}), 400

    source_id = session["user_id"]
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (target_username,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "target user not found"}), 404
        target_id = row[0]
        if target_id == source_id:
            return jsonify({"error": "cannot sync to self"}), 400

        # Upsert favorites (don't overwrite target's existing categories).
        cur.execute("""
            INSERT INTO user_favorites (user_id, listing_id, category, created_at)
            SELECT %s, listing_id, category, created_at
            FROM user_favorites WHERE user_id = %s
            ON CONFLICT (user_id, listing_id) DO NOTHING
        """, (target_id, source_id))
        copied_favs = cur.rowcount

        # Upsert notes.
        cur.execute("""
            INSERT INTO user_notes (user_id, listing_id, note, updated_at)
            SELECT %s, listing_id, note, updated_at
            FROM user_notes WHERE user_id = %s
            ON CONFLICT (user_id, listing_id) DO NOTHING
        """, (target_id, source_id))
        copied_notes = cur.rowcount

        conn.commit()

    return jsonify({
        "ok": True,
        "target": target_username,
        "copied": copied_favs,
        "copied_notes": copied_notes,
    })


# --- Static files / index ---

@app.route("/")
def index():
    if not session.get("user_id"):
        return redirect(url_for("login_page"))
    return redirect("/listings/search.html")


@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory("static", path)


# --- Serve listings/ directory (server-synced frontend) ---
# Files synced into render_server/static/listings/ by sync_to_render.py.
# Falls back to sibling ../listings/ dir for local dev without sync.
from pathlib import Path as _Path
_LISTINGS_DIR = _Path(__file__).parent / "static" / "listings"
if not _LISTINGS_DIR.exists():
    _LISTINGS_DIR = _Path(__file__).parent.parent / "listings"


@app.route("/listings/")
@login_required
def listings_index():
    return send_from_directory(str(_LISTINGS_DIR), "index.html")


@app.route("/listings/<path:filename>")
@login_required
def serve_listing(filename):
    return send_from_directory(str(_LISTINGS_DIR), filename)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5555)))
