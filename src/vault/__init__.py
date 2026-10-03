from __future__ import annotations

from datetime import datetime, timedelta

from src.models import AuditLog


def get_recent_security_events(limit=20):
    return AuditLog.query.order_by(AuditLog.created_at.desc()).limit(limit).all()


def get_failed_login_count_for_last_day():
    cutoff = datetime.utcnow() - timedelta(days=1)
    return AuditLog.query.filter(AuditLog.event_type == "login_failure", AuditLog.created_at >= cutoff).count()
