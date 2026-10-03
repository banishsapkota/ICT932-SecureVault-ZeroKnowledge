from __future__ import annotations

import re
from datetime import datetime

import pyotp
from argon2 import PasswordHasher


ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32)


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except Exception:
        return False


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(str(code).strip(), valid_window=1)
    except Exception:
        return False


def validate_password_strength(password: str) -> dict:
    score = 0
    reasons = []

    if len(password) >= 12:
        score += 1
    else:
        reasons.append("Use at least 12 characters.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        reasons.append("Include lowercase letters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        reasons.append("Include uppercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        reasons.append("Include digits.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        reasons.append("Include a special character.")

    entropy = len(password) * 4
    is_strong = score >= 4 and entropy >= 48
    return {
        "score": score,
        "entropy": entropy,
        "is_strong": is_strong,
        "reasons": reasons,
        "label": "Strong" if is_strong else "Weak",
        "checked_at": datetime.utcnow().isoformat(),
    }
