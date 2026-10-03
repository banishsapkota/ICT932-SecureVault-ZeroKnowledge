from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "replace-with-strong-random-value")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'securevault.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False").strip().lower() in {"1", "true", "yes"}
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    SESSION_REFRESH_EACH_REQUEST = True

    WTF_CSRF_TIME_LIMIT = 3600
    WTF_CSRF_ENABLED = True

    AES_KEY = os.getenv("AES_KEY", "")
    TOTP_ISSUER = os.getenv("TOTP_ISSUER", "SecureVault-ICT932")
    APP_ENV = os.getenv("APP_ENV", "development")

    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_SECONDS = 900

    JSON_SORT_KEYS = False
