import base64
import secrets
import pytest
from src.models import VaultEntry, AuditLog


def envelope():
    return {
        "ciphertext": base64.b64encode(secrets.token_bytes(32)).decode(),
        "nonce": base64.b64encode(secrets.token_bytes(12)).decode(),
    }


def test_storage_ownership_and_delete(app, client, register):
    register()
    assert client.post("/api/vault/key-check", json=envelope()).status_code == 201
    assert client.post("/api/vault/key-check", json=envelope()).status_code == 409
    data = envelope()
    response = client.post("/api/vault", json=data)
    assert response.status_code == 201
    entry_id = response.json["id"]
    assert VaultEntry.query.one().ciphertext == data["ciphertext"]
    assert client.get("/api/vault").json == [dict(id=entry_id, **data)]
    assert client.post("/api/vault", json=data).status_code == 409
    register("bob")
    assert client.get("/api/vault").json == []
    assert client.delete(f"/api/vault/{entry_id}").status_code == 404
    assert VaultEntry.query.count() == 1
    assert data["ciphertext"] not in str([(a.event_type, a.details) for a in AuditLog.query.all()])


@pytest.mark.parametrize(
    "data",
    [
        [],
        {},
        {"ciphertext": "!!!", "nonce": "bad"},
        {"ciphertext": "YQ==", "nonce": "YQ=="},
        {"ciphertext": 123, "nonce": None},
        dict(envelope(), password="plaintext"),
    ],
)
def test_invalid_envelopes(client, register, data):
    register()
    assert client.post("/api/vault/key-check", json=data).status_code == 400


def test_delete_owned(client, register):
    register()
    client.post("/api/vault/key-check", json=envelope())
    entry = client.post("/api/vault", json=envelope()).json
    assert client.delete(f"/api/vault/{entry['id']}").status_code == 204
    assert client.get("/api/vault").json == []
