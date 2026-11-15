from __future__ import annotations

import io
import os
import sqlite3

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-module-import-only-1234567890")

import bcrypt
import pytest

from flask_server import create_app


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret-key-that-is-at-least-32-characters-long",
            "DATABASE": str(tmp_path / "test.db"),
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            "WTF_CSRF_ENABLED": False,
            "BCRYPT_ROUNDS": 4,
            "MAX_CONTENT_LENGTH": 1024 * 1024,
        }
    )
    with application.app_context():
        from flask import current_app

        with sqlite3.connect(current_app.config["DATABASE"]) as database:
            database.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                ("tester", bcrypt.hashpw(b"correct-horse-battery", bcrypt.gensalt(rounds=4)), "2026-01-01T00:00:00+00:00"),
            )
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client):
    return client.post(
        "/login",
        data={"username": "tester", "password": "correct-horse-battery"},
        follow_redirects=True,
    )


def test_dashboard_requires_authentication(client):
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_and_security_headers(client):
    response = login(client)
    assert response.status_code == 200
    assert b"Hosted files" in response.data
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_notes_are_persisted_and_autoescaped(client):
    login(client)
    response = client.post(
        "/comment",
        data={"comment": '<script>alert("xss")</script>'},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"&lt;script&gt;" in response.data
    assert b"<script>alert" not in response.data


def test_upload_is_authenticated_and_downloaded_as_attachment(client):
    login(client)
    upload_response = client.post(
        "/upload",
        data={"file": (io.BytesIO(b"safe test content"), "example.txt")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert upload_response.status_code == 200
    assert b"example.txt" in upload_response.data

    with client.session_transaction() as session:
        assert session.get("user_id")

    from flask import current_app

    with client.application.app_context():
        database = sqlite3.connect(current_app.config["DATABASE"])
        row = database.execute("SELECT id FROM hosted_files").fetchone()
        database.close()

    download_response = client.get(f"/files/{row[0]}")
    assert download_response.status_code == 200
    assert download_response.data == b"safe test content"
    assert "attachment" in download_response.headers["Content-Disposition"]
    assert download_response.mimetype == "application/octet-stream"


def test_active_content_extensions_are_rejected(client):
    login(client)
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(b"<script>alert(1)</script>"), "payload.html")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"This file extension is not allowed" in response.data


def test_csrf_is_required_when_enabled(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret-key-that-is-at-least-32-characters-long",
            "DATABASE": str(tmp_path / "csrf.db"),
            "UPLOAD_FOLDER": str(tmp_path / "csrf-uploads"),
            "WTF_CSRF_ENABLED": True,
            "BCRYPT_ROUNDS": 4,
        }
    )
    response = application.test_client().post(
        "/login",
        data={"username": "tester", "password": "wrong"},
    )
    assert response.status_code == 400


def test_legacy_database_schema_is_migrated(tmp_path):
    database_path = tmp_path / "legacy.db"
    legacy_hash = bcrypt.hashpw(b"legacy-password-123", bcrypt.gensalt(rounds=4)).decode("ascii")
    with sqlite3.connect(database_path) as database:
        database.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)"
        )
        database.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("legacy", legacy_hash),
        )

    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret-key-that-is-at-least-32-characters-long",
            "DATABASE": str(database_path),
            "UPLOAD_FOLDER": str(tmp_path / "legacy-uploads"),
            "WTF_CSRF_ENABLED": False,
            "BCRYPT_ROUNDS": 4,
        }
    )
    client = application.test_client()
    response = client.post(
        "/login",
        data={"username": "legacy", "password": "legacy-password-123"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Hosted files" in response.data
