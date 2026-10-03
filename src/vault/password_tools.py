from __future__ import annotations

import base64
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _decode_key(key_material: str) -> bytes:
    if len(key_material) != 64:
        raise ValueError("AES key must be a 64-character hexadecimal string for AES-256.")
    return bytes.fromhex(key_material)


def encrypt_secret(secret: str, key_material: str) -> dict:
    key = _decode_key(key_material)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, secret.encode("utf-8"), None)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
    }


def decrypt_secret(ciphertext_b64: str, nonce_b64: str, key_material: str) -> str:
    key = _decode_key(key_material)
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
