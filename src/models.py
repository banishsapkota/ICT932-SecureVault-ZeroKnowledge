from datetime import datetime, timezone
import secrets
import pyotp
from flask_login import UserMixin
from src.extensions import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    totp_secret = db.Column(db.String(64), nullable=False, default=pyotp.random_base32)
    two_factor_enabled = db.Column(db.Boolean, nullable=False, default=False)
    last_totp_step = db.Column(db.BigInteger, nullable=False, default=-1)
    vault_salt = db.Column(db.String(64), nullable=False, default=lambda: secrets.token_urlsafe(32))
    vault_check = db.Column(db.Text)
    vault_check_nonce = db.Column(db.String(24))
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False
    )
    locked_until = db.Column(db.DateTime)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)

    @property
    def is_active(self):
        return self.locked_until is None or self.locked_until <= datetime.now(timezone.utc).replace(
            tzinfo=None
        )


class VaultEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    ciphertext = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.String(24), nullable=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False
    )
    __table_args__ = (db.UniqueConstraint("user_id", "nonce"),)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    event_type = db.Column(db.String(64), nullable=False)
    details = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False
    )


AuditEvent = AuditLog
