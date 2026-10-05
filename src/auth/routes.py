import base64
import io
import re
import time
from datetime import datetime, timedelta, timezone
import pyotp
import qrcode
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import login_required, login_user, logout_user, current_user
from sqlalchemy.exc import IntegrityError
from src.extensions import db, limiter
from src.models import User
from src.auth.security import hash_password, verify_password
from src.security.audit import log_security_event

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def pending(user):
    session.clear()
    session["pending_user"] = user.id
    session["pending_since"] = time.time()
    session.permanent = True


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,80}", username) or not 12 <= len(password) <= 128:
            flash("Use a 3–80 character username and a 12–128 character password.")
            return render_template("register.html"), 400
        user = User(username=username, password_hash=hash_password(password))
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Username unavailable.")
            return render_template("register.html"), 400
        log_security_event(user.id, "registration")
        pending(user)
        return redirect(url_for("auth.two_factor"))
    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        session.clear()
        user = User.query.filter_by(username=request.form.get("username", "").strip()).first()
        password = request.form.get("password", "")
        if (
            user
            and user.is_active
            and len(password) <= 128
            and verify_password(password, user.password_hash)
        ):
            pending(user)
            return redirect(url_for("auth.two_factor"))
        if user and user.is_active:
            user.failed_login_count += 1
            if user.failed_login_count >= 5:
                user.locked_until = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(
                    minutes=15
                )
                user.failed_login_count = 0
            db.session.commit()
        log_security_event(user.id if user else None, "login_failure")
        flash("Invalid credentials or temporarily locked account.")
        return render_template("login.html"), 401
    return render_template("login.html")


@auth_bp.route("/two-factor", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def two_factor():
    user = (
        db.session.get(User, session.get("pending_user")) if session.get("pending_user") else None
    )
    if not user or not user.is_active or time.time() - session.get("pending_since", 0) > 300:
        session.clear()
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        code = request.form.get("token", "")
        step = int(time.time()) // 30
        matched = next(
            (
                s
                for s in (step - 1, step, step + 1)
                if re.fullmatch(r"[0-9]{6}", code)
                and pyotp.TOTP(user.totp_secret).verify(code, for_time=s * 30)
            ),
            None,
        )
        if matched is not None:
            # Atomic consume prevents concurrent replay of a TOTP time step.
            changed = User.query.filter(User.id == user.id, User.last_totp_step < matched).update(
                {
                    User.last_totp_step: matched,
                    User.two_factor_enabled: True,
                    User.failed_login_count: 0,
                },
                synchronize_session=False,
            )
            db.session.commit()
            if changed:
                session.clear()
                session.permanent = True
                login_user(user, remember=False)
                log_security_event(user.id, "login_success")
                return redirect(url_for("dashboard"))
        user.failed_login_count += 1
        if user.failed_login_count >= 5:
            user.locked_until = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(
                minutes=15
            )
            user.failed_login_count = 0
            session.clear()
        db.session.commit()
        log_security_event(user.id, "2fa_failure")
        flash("Invalid or already used code. Wait for a new code before retrying.")
    qr = secret = None
    if not user.two_factor_enabled:
        secret = user.totp_secret
        uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="SecureVault")
        buffer = io.BytesIO()
        qrcode.make(uri).save(buffer, format="PNG")
        qr = base64.b64encode(buffer.getvalue()).decode()
    return render_template("two_factor.html", qr=qr, secret=secret)


@auth_bp.post("/logout")
@login_required
def logout():
    log_security_event(current_user.id, "logout")
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))
