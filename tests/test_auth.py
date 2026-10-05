import time
import pyotp
from src.extensions import db
from src.models import User


def test_registration_requires_totp(client):
    assert (
        client.post(
            "/auth/register",
            data={"username": "alice", "password": "Strong password 123!", "role": "admin"},
        ).status_code
        == 302
    )
    user = User.query.one()
    assert user.role == "user" and user.password_hash.startswith("$argon2id$")
    assert client.get("/api/vault").status_code == 401
    setup = client.get("/auth/two-factor")
    assert b"data:image/png" in setup.data
    assert client.post("/auth/two-factor", data={"token": "bad"}).status_code == 200
    assert client.get("/api/vault").status_code == 401
    assert (
        client.post(
            "/auth/two-factor", data={"token": pyotp.TOTP(user.totp_secret).now()}
        ).status_code
        == 302
    )
    assert client.get("/dashboard").status_code == 200
    assert client.get("/api/vault").status_code == 200


def test_replay_logout_and_pending_expiry(client, register):
    user = register()
    code = pyotp.TOTP(user.totp_secret).now()
    assert client.get("/auth/logout").status_code == 405
    client.post("/auth/logout")
    assert client.get("/api/vault").status_code == 401
    client.post("/auth/login", data={"username": "alice", "password": "Strong password 123!"})
    assert user.totp_secret.encode() not in client.get("/auth/two-factor").data
    client.post("/auth/two-factor", data={"token": code})
    assert client.get("/api/vault").status_code == 401
    with client.session_transaction() as session:
        session["pending_since"] = time.time() - 301
    assert client.get("/auth/two-factor").status_code == 302


def test_bad_registration_and_lockout(client, register):
    assert (
        client.post("/auth/register", data={"username": "alice", "password": "short"}).status_code
        == 400
    )
    user = register()
    client.post("/auth/logout")
    for _ in range(5):
        assert (
            client.post("/auth/login", data={"username": "alice", "password": "wrong"}).status_code
            == 401
        )
    db.session.refresh(user)
    assert not user.is_active
    assert (
        client.post(
            "/auth/login", data={"username": "alice", "password": "Strong password 123!"}
        ).status_code
        == 401
    )


def test_admin_role_and_lock_revokes_session(app, client, register):
    alice = register()
    assert client.get("/admin/dashboard").status_code == 403
    other = app.test_client()
    other.post("/auth/register", data={"username": "admin", "password": "Strong password 123!"})
    admin = User.query.filter_by(username="admin").one()
    admin.role = "admin"
    db.session.commit()
    other.post("/auth/two-factor", data={"token": pyotp.TOTP(admin.totp_secret).now()})
    assert other.get("/admin/dashboard").status_code == 200
    assert other.post(f"/admin/user/{alice.id}/lock").status_code == 302
    assert client.get("/api/vault").status_code == 401
