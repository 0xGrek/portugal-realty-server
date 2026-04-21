"""Integration tests for public /demo route with localStorage-only state.

Reuses the FakeConn/FakeCursor infrastructure from test_auth.py to keep DB
contact isolated. Demo route must:
  - Set session flags without touching DB
  - Return 403 on any mutation endpoint
  - Return empty state on read endpoints without SQL errors
  - Clear cleanly on logout

Run: pytest tests/test_demo_route.py -v
"""
import os
import unittest.mock as mock

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("NEON_DATABASE_URL", "postgresql://fake")
os.environ.setdefault("APP_ADMIN_PASSWORD", "testpass123")


_users = {}
_id = [0]


class FakeCursor:
    """Minimal fake — shared with test_auth.py conceptually but kept local."""

    def __init__(self):
        self._res = None
        self._rows = []
        self.rowcount = 0

    def execute(self, sql, params=None):
        s = sql.lower().strip()
        p = params or ()
        self.rowcount = 0
        self._res = None
        self._rows = []

        if "create table" in s or "create index" in s:
            return
        if "select count(*) from users" in s:
            self._res = (len(_users),)
            return
        if s.startswith("insert into users"):
            _id[0] += 1
            uid = _id[0]
            is_admin = bool(p[2]) if len(p) > 2 else True
            _users[p[0]] = {"id": uid, "hash": p[1], "is_admin": is_admin}
            self._res = (uid,)
            self.rowcount = 1
            return
        if "select id, username, password_hash, is_admin from users where username" in s:
            u = _users.get(p[0])
            if u:
                self._res = (u["id"], p[0], u["hash"], u["is_admin"])
            return
        if "update users set last_login" in s:
            self.rowcount = 1
            return

    def fetchone(self):
        return self._res

    def fetchall(self):
        return self._rows

    def close(self):
        pass


class FakeConn:
    def cursor(self):
        return FakeCursor()

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


@pytest.fixture
def client():
    _users.clear()
    _id[0] = 0
    with mock.patch("psycopg2.connect", return_value=FakeConn()):
        import importlib

        import app

        importlib.reload(app)
        yield app.app.test_client()


# --- Route entry ---

def test_demo_redirects_to_search(client):
    r = client.get("/demo", follow_redirects=False)
    assert r.status_code == 302
    assert "/listings/search.html" in r.headers.get("Location", "")


def test_demo_sets_session_flag(client):
    client.get("/demo")
    with client.session_transaction() as sess:
        assert sess.get("is_demo") is True
        assert sess.get("user_id") == "demo"
        assert sess.get("username") == "Demo Guest"
        assert sess.get("is_admin") is False


def test_demo_me_returns_is_demo_true(client):
    client.get("/demo")
    r = client.get("/api/me")
    assert r.status_code == 200
    data = r.get_json()
    assert data["is_demo"] is True
    assert data["username"] == "Demo Guest"
    assert "csrf_token" in data


# --- Read endpoints work (empty) ---

def test_demo_state_returns_empty_not_500(client):
    """Even though user_id='demo' is not a valid INTEGER, /api/state must not
    crash on DB — should short-circuit to empty maps."""
    client.get("/demo")
    r = client.get("/api/state")
    assert r.status_code == 200
    data = r.get_json()
    assert data == {
        "favs": {}, "maybe": {}, "blocked": {},
        "contacted": {}, "saved": {}, "notes": {},
    }


def test_demo_favorites_list_returns_empty(client):
    client.get("/demo")
    r = client.get("/api/favorites")
    assert r.status_code == 200
    assert r.get_json() == {"favorites": []}


def test_demo_notes_list_returns_empty(client):
    client.get("/demo")
    r = client.get("/api/notes")
    assert r.status_code == 200
    assert r.get_json() == {"notes": []}


# --- Mutation endpoints blocked ---

def test_demo_cannot_post_favorite(client):
    client.get("/demo")
    with client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")
    r = client.post(
        "/api/favorites",
        json={"listing_id": "abc123", "category": "saved"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403
    assert r.get_json().get("error") == "demo_mode"


def test_demo_cannot_toggle_fav(client):
    client.get("/demo")
    with client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")
    r = client.post("/api/fav/abc123", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403


def test_demo_cannot_post_note(client):
    client.get("/demo")
    with client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")
    r = client.post(
        "/api/notes",
        json={"listing_id": "abc", "note": "hello"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403


def test_demo_cannot_access_admin(client):
    client.get("/demo")
    r = client.get("/admin")
    assert r.status_code == 403


def test_demo_cannot_create_user(client):
    client.get("/demo")
    with client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")
    r = client.post(
        "/api/admin/users",
        json={"username": "hax", "password": "hax12345"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403


def test_demo_cannot_sync(client):
    client.get("/demo")
    with client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")
    r = client.post(
        "/api/sync",
        json={"target_username": "serhii"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403


# --- Logout ---

def test_demo_logout_clears_session(client):
    client.get("/demo")
    client.get("/logout", follow_redirects=False)
    with client.session_transaction() as sess:
        assert sess.get("is_demo") is None
        assert sess.get("user_id") is None
    # After logout /api/state must 401, not return demo data.
    r = client.get("/api/state")
    assert r.status_code == 401


# --- Regression: regular users unaffected ---

def test_regular_user_login_not_flagged_as_demo(client):
    r = client.post("/api/login", json={"username": "serhii", "password": "testpass123"})
    assert r.status_code == 200
    r = client.get("/api/me")
    assert r.status_code == 200
    assert r.get_json()["is_demo"] is False
