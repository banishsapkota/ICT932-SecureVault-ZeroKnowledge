import re
from flask import request, has_request_context
from src.extensions import db
from src.models import AuditLog


def sanitize_details(details):
    if details is None:
        return None
    return re.sub(
        r"(?i)(password|secret|otp|token|key)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", str(details)
    )[:255]


def log_security_event(user_id, event_type, details=None, incoming_request=None):
    source = incoming_request or (request if has_request_context() else None)
    db.session.add(
        AuditLog(
            user_id=user_id,
            event_type=event_type,
            details=sanitize_details(details),
            ip_address=source.remote_addr if source else None,
        )
    )
    db.session.commit()
