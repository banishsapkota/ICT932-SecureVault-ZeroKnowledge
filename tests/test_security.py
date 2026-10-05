import re
import pytest
from src.app import create_app
from src.auth.security import hash_password, verify_password
from src.security.audit import sanitize_details


def test_argon2():
    hashed = hash_password("example password")
    assert verify_password("example password", hashed)
    assert not verify_password("incorrect", hashed)
    assert not verify_password("anything", "invalid hash")


def test_csrf_and_headers(app, client, register):
    register()
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/auth/logout").status_code == 400
    assert client.post("/api/vault", json={}).status_code == 400
    response = client.get("/dashboard")
    assert response.headers["Cache-Control"] == "no-store"
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    token = re.search(rb'name="csrf-token" content="([^"]+)"', response.data).group(1).decode()
    assert client.post("/auth/logout", headers={"X-CSRFToken": token}).status_code == 302


def test_config_and_redaction(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "short")
    with pytest.raises(ValueError):
        create_app()
    assert "sensitive" not in sanitize_details("password=sensitive token=sensitive")


def test_rate_limit():
    from src.extensions import db

    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "t" * 32,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "WTF_CSRF_ENABLED": False,
            "RATELIMIT_ENABLED": True,
        }
    )
    with app.app_context():
        db.create_all()
    client = app.test_client()
    for _ in range(5):
        client.post("/auth/login", data={"username": "missing", "password": "wrong"})
    assert (
        client.post("/auth/login", data={"username": "missing", "password": "wrong"}).status_code
        == 429
    )

    with app.app_context():
        db.session.remove()
        db.engine.dispose()
