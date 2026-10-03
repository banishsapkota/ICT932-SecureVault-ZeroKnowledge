from __future__ import annotations

from datetime import datetime

from flask_login import UserMixin

from src.extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), nullable=False, default="user")
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    totp_secret = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    is_active_flag = db.Column(db.Boolean, default=True, nullable=False)

    vault_entries = db.relationship("VaultEntry", backref="user", lazy=True, cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", backref="user", lazy=True, cascade="all, delete-orphan")

    @property
    def is_active(self):
        return self.is_active_flag and (self.locked_until is None or self.locked_until <= datetime.utcnow())

    @property
    def is_admin(self):
        return self.role == "admin"


class VaultEntry(db.Model):
    __tablename__ = "vault_entries"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    url = db.Column(db.String(255), nullable=True)
    username = db.Column(db.String(120), nullable=True)
    password_ciphertext = db.Column(db.Text, nullable=False)
    password_nonce = db.Column(db.String(128), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    event_type = db.Column(db.String(80), nullable=False)
    details = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
