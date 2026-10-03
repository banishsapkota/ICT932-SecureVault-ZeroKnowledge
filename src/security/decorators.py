from __future__ import annotations

import re
from datetime import datetime

from flask import request

from src.extensions import db
from src.models import AuditLog


def sanitize_details(details: str | None) -> str | None:
    if details is None:
        return None
    redacted = re.sub(r"(?i)(password|secret|otp|token|key)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", details)
    redacted = re.sub(r"(?i)\b(\d{6,8})\b", "[OTP_REDACTED]", redacted)
    return redacted[:255]


def log_security_event(user_id, event_type: str, details: str | None = None, incoming_request=None):
    if incoming_request is not None:
        source_ip = incoming_request.remote_addr
    else:
        source_ip = request.remote_addr if request else None

    event = AuditLog(
        user_id=user_id,
        event_type=event_type,
        details=sanitize_details(details),
        ip_address=source_ip,
        created_at=datetime.utcnow(),
    )
    db.session.add(event)
    db.session.commit()
