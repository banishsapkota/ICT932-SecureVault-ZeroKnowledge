from datetime import datetime, timedelta, timezone
from flask import Blueprint, flash, redirect, render_template, url_for, abort
from flask_login import current_user, login_required
from src.extensions import db
from src.models import AuditLog, User
from src.security.audit import log_security_event
from src.security.decorators import admin_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.get("/dashboard")
@login_required
@admin_required
def dashboard():
    return render_template(
        "admin_dashboard.html",
        users=User.query.all(),
        logs=AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all(),
    )


@admin_bp.post("/user/<int:user_id>/lock")
@login_required
@admin_required
def lock_user(user_id):
    if user_id == current_user.id:
        abort(400)
    user = db.get_or_404(User, user_id)
    user.locked_until = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=15)
    db.session.commit()
    log_security_event(current_user.id, "administrative_action", f"locked_user_id={user_id}")
    flash("Account locked for 15 minutes.")
    return redirect(url_for("admin.dashboard"))
