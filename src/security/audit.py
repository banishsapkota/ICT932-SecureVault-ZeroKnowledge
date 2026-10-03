from __future__ import annotations

import base64
import io

import pyotp
import qrcode
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from src.extensions import db, limiter
from src.models import AuditLog, User
from src.auth.forms import LoginForm, RegistrationForm, TwoFactorForm
from src.auth.security import generate_totp_secret, hash_password, validate_password_strength, verify_password, verify_totp
from src.security.audit import log_security_event


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        normalized_email = form.email.data.strip().lower()
        if User.query.filter((User.email == normalized_email) | (User.username == form.username.data.strip())).first():
            flash("An account with that email or username already exists.")
            return render_template("register.html", form=form)

        password_check = validate_password_strength(form.password.data)
        if not password_check["is_strong"]:
            flash("Password is too weak. " + " ".join(password_check["reasons"]))
            return render_template("register.html", form=form)

        user = User(
            username=form.username.data.strip(),
            email=normalized_email,
            password_hash=hash_password(form.password.data),
            role="user",
        )
        db.session.add(user)
        db.session.commit()
        log_security_event(user.id, "login_success", "new user registered", request)
        flash("Registration successful. Please log in.")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5/minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if user and user.is_active:
            if verify_password(form.password.data, user.password_hash):
                user.failed_login_count = 0
                user.locked_until = None
                db.session.commit()
                if user.totp_secret:
                    session["pending_2fa_user_id"] = user.id
                    log_security_event(user.id, "login_success", "password_verified_awaiting_2fa", request)
                    flash("Password accepted. Please verify your authenticator code.")
                    return redirect(url_for("auth.verify_2fa"))
                login_user(user, remember=form.remember.data)
                user.last_login_at = __import__("datetime").datetime.utcnow()
                db.session.commit()
                log_security_event(user.id, "login_success", "login_completed", request)
                flash("Login successful.")
                return redirect(url_for("dashboard"))

            user.failed_login_count += 1
            if user.failed_login_count >= 5:
                user.locked_until = __import__("datetime").datetime.utcnow().replace(microsecond=0)
                log_security_event(user.id, "login_failure", "account_locked_after_repeated_failures", request)
                flash("Too many failed attempts. Your account is temporarily locked.")
            else:
                log_security_event(user.id, "login_failure", f"failed_attempt_{user.failed_login_count}", request)
                flash("Invalid email or password.")
            db.session.commit()
            return render_template("login.html", form=form)

        log_security_event(None, "login_failure", "unknown_account_or_inactive_user", request)
        flash("Invalid email or password.")
        return render_template("login.html", form=form)

    return render_template("login.html", form=form)


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
@login_required
def verify_2fa():
    if "pending_2fa_user_id" not in session:
        return redirect(url_for("dashboard"))

    user = User.query.get(session["pending_2fa_user_id"])
    form = TwoFactorForm()
    if form.validate_on_submit():
        if verify_totp(user.totp_secret, form.otp.data):
            login_user(user, remember=True)
            session.pop("pending_2fa_user_id", None)
            user.last_login_at = __import__("datetime").datetime.utcnow()
            db.session.commit()
            log_security_event(user.id, "login_success", "2fa_verified", request)
            flash("Two-factor authentication successful.")
            return redirect(url_for("dashboard"))
        log_security_event(user.id, "2fa_failure", "invalid_code", request)
        flash("Invalid 2FA code. Please try again.")

    return render_template("verify_2fa.html", form=form)


@auth_bp.route("/setup-2fa")
@login_required
def setup_2fa():
    if not current_user.totp_secret:
        current_user.totp_secret = generate_totp_secret()
        db.session.commit()

    totp = pyotp.TOTP(current_user.totp_secret)
    uri = totp.provisioning_uri(name=current_user.email, issuer_name="SecureVault")
    qr_img = qrcode.make(uri)
    buffer = io.BytesIO()
    qr_img.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return render_template("setup_2fa.html", qr_code=qr_b64, otp_uri=uri)


@auth_bp.route("/logout")
@login_required
def logout():
    log_security_event(current_user.id, "logout", "user_logged_out", request)
    logout_user()
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("auth.login"))
