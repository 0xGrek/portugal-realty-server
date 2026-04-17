"""Integration tests for multi-user auth in app.py.

Uses in-memory fake DB to avoid hitting Neon.
Run: pytest tests/test_auth.py -v
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
    """Minimal fake cursor that handles the SQL patterns app.py uses."""

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

        if "update users set last_login" in s or "update users set password_hash" in s:
            self.rowcount = 1
            return

        if "insert into user_favorites" in s or "insert into user_notes" in s:
            self.rowcount = 1
            return

        if (
            "select listing_id, category from user_favorites" in s
            or "select listing_id, note from user_notes" in s
        ):
            self._rows = []
            return

        if "select id, username, is_admin, created_at, last_login from users" in s:
            self._rows = [
                (u["id"], un, u["is_admin"], None, None) for un, u in _users.items()
            ]
            return

        if "delete from" in s:
            self.rowcount = 0
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
        # Re-import so _seed_admin runs on fresh state.
        import importlib

        import app

        importlib.reload(app)
        yield app.app.test_client()


def test_wrong_password_returns_401(client):
    r = client.post("/api/login", json={"username": "serhii", "password": "wrong"})
    assert r.status_code == 401


def test_admin_login_returns_csrf(client):
    r = client.post("/api/login", json={"username": "serhii", "password": "testpass123"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["is_admin"] is True
    assert "csrf_token" in data


def test_state_endpoint_returns_user_categories(client):
    client.post("/api/login", json={"username": "serhii", "password": "testpass123"})
    r = client.get("/api/state")
    assert r.status_code == 200
    keys = set(r.get_json().keys())
    assert keys >= {"favs", "maybe", "blocked", "contacted", "saved", "notes"}


def test_csrf_blocks_post_without_token(client):
    client.post("/api/login", json={"username": "serhii", "password": "testpass123"})
    r = client.post("/api/favorites", json={"listing_id": "id1", "category": "saved"})
    assert r.status_code == 403


def test_csrf_allows_post_with_token(client):
    r = client.post("/api/login", json={"username": "serhii", "password": "testpass123"})
    csrf = r.get_json()["csrf_token"]
    r = client.post(
        "/api/favorites",
        json={"listing_id": "id1", "category": "saved"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200


def test_admin_can_create_user(client):
    r = client.post("/api/login", json={"username": "serhii", "password": "testpass123"})
    csrf = r.get_json()["csrf_token"]
    r = client.post(
        "/api/admin/users",
        json={"username": "violeta", "password": "violeta8chars"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200


def test_short_password_rejected(client):
    r = client.post("/api/login", json={"username": "serhii", "password": "testpass123"})
    csrf = r.get_json()["csrf_token"]
    r = client.post(
        "/api/admin/users",
        json={"username": "weak", "password": "short"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 400


def test_logout_clears_session(client):
    client.post("/api/login", json={"username": "serhii", "password": "testpass123"})
    client.get("/logout", follow_redirects=False)
    r = client.get("/api/state")
    assert r.status_code == 401


def test_rate_limit_after_5_attempts(client):
    last = None
    for _ in range(6):
        last = client.post(
            "/api/login", json={"username": "nobody", "password": "x"}
        )
    assert last.status_code == 429
