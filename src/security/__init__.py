from __future__ import annotations

from flask import Blueprint, flash, render_template, request
from flask_login import current_user, login_required

from src.extensions import db
from src.models import AuditLog, User
from src.security.audit import log_security_event
from src.security.decorators import admin_required


admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/dashboard")
@login_required
@admin_required
def dashboard():
    users = User.query.order_by(User.created_at.desc()).all()
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(50).all()
    return render_template("admin_dashboard.html", users=users, logs=logs)


@admin_bp.route("/user/<int:user_id>/lock", methods=["POST"])
@login_required
@admin_required
def lock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.locked_until = __import__("datetime").datetime.utcnow()
    db.session.commit()
    log_security_event(current_user.id, "administrative_action", f"locked_user_id={user_id}", request)
    flash(f"User {user.username} was locked.")
    return dashboard()
