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


def test_public_static_route_does_not_expose_listing_assets(client):
    assert client.get("/static/login.html").status_code == 200
    assert client.get("/static/admin.html").status_code == 401
    assert client.get("/static/index.html").status_code == 401
    assert client.get("/static/listings/data.json").status_code == 401


def test_data_json_uses_private_cache_headers(client, tmp_path):
    import app as app_module

    old_listings_dir = app_module._LISTINGS_DIR
    (tmp_path / "data.json").write_text(
        '[{"id":"1","region_match":1}]', encoding="utf-8"
    )
    app_module._LISTINGS_DIR = tmp_path
    try:
        client.post("/api/login", json={"username": "serhii", "password": "testpass123"})
        r = client.get("/listings/data.json")
    finally:
        app_module._LISTINGS_DIR = old_listings_dir

    assert r.status_code == 200
    assert r.headers["Cache-Control"].startswith("private")
    assert "Cookie" in r.headers["Vary"]


def test_listings_search_api_returns_sliced_results(client, tmp_path):
    import app as app_module

    old_listings_dir = app_module._LISTINGS_DIR
    (tmp_path / "data.json").write_text(
        """
        [
          {"id":"1","price":100000,"district":"Lisboa","region_match":1,"days":10},
          {"id":"2","price":200000,"district":"Porto","region_match":0,"days":20},
          {"id":"3","price":300000,"district":"Lisboa","region_match":null,"days":30}
        ]
        """,
        encoding="utf-8",
    )
    app_module._LISTINGS_DIR = tmp_path
    try:
        client.post("/api/login", json={"username": "serhii", "password": "testpass123"})
        r = client.get("/api/listings/search?shelf=all&limit=2&offset=1&sort=price_asc")
    finally:
        app_module._LISTINGS_DIR = old_listings_dir

    assert r.status_code == 200
    data = r.get_json()
    assert data["all_total"] == 3
    assert data["total"] == 3
    assert data["offset"] == 1
    assert data["limit"] == 2
    assert [item["id"] for item in data["items"]] == ["2", "3"]
    assert data["has_more"] is False


def test_listings_meta_returns_district_counts(client, tmp_path):
    import app as app_module

    old_listings_dir = app_module._LISTINGS_DIR
    (tmp_path / "data.json").write_text(
        '[{"id":"1","district":"Lisboa","district_recommendation":"TOP"},'
        '{"id":"2","district":"Lisboa"},'
        '{"id":"3","district":"Porto","district_recommendation":"BUY"}]',
        encoding="utf-8",
    )
    app_module._LISTINGS_DIR = tmp_path
    try:
        client.post("/api/login", json={"username": "serhii", "password": "testpass123"})
        r = client.get("/api/listings/meta")
    finally:
        app_module._LISTINGS_DIR = old_listings_dir

    assert r.status_code == 200
    data = r.get_json()
    assert data["all_total"] == 3
    assert data["districts"][0] == {"d": "Lisboa", "c": 2}
    assert data["tier_counts"]["TOP"] == 1
    assert data["tier_counts"]["BUY"] == 1
    assert data["tier_counts"]["NONE"] == 1


def test_legacy_district_html_redirects_to_search(client):
    client.post("/api/login", json={"username": "serhii", "password": "testpass123"})

    r = client.get("/listings/lisboa.html", follow_redirects=False)

    assert r.status_code == 302
    assert r.headers["Location"].endswith("/listings/search.html")


def test_sync_requires_admin_user(client):
    r = client.post("/api/login", json={"username": "serhii", "password": "testpass123"})
    csrf = r.get_json()["csrf_token"]
    r = client.post(
        "/api/admin/users",
        json={"username": "viewer", "password": "viewerpass"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200

    client.get("/logout", follow_redirects=False)
    r = client.post("/api/login", json={"username": "viewer", "password": "viewerpass"})
    csrf = r.get_json()["csrf_token"]
    r = client.post(
        "/api/sync",
        json={"target_username": "serhii"},
        headers={"X-CSRF-Token": csrf},
    )

    assert r.status_code == 403
