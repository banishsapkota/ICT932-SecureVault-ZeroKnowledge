import base64
import binascii
from flask import Blueprint, abort, jsonify, request
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError
from src.extensions import db
from src.models import User, VaultEntry
from src.security.audit import log_security_event

vault_bp = Blueprint("vault", __name__, url_prefix="/api/vault")


def envelope():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"ciphertext", "nonce"}:
        abort(400)
    try:
        if any(not isinstance(v, str) for v in data.values()):
            abort(400)
        ciphertext = base64.b64decode(data["ciphertext"], validate=True)
        nonce = base64.b64decode(data["nonce"], validate=True)
        if not 17 <= len(ciphertext) <= 65536 or len(nonce) != 12:
            abort(400)
    except (ValueError, binascii.Error):
        abort(400)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
    }


@vault_bp.get("/key-check")
@login_required
def key_check():
    return jsonify(
        salt=current_user.vault_salt,
        ciphertext=current_user.vault_check,
        nonce=current_user.vault_check_nonce,
    )


@vault_bp.post("/key-check")
@login_required
def initialize_key():
    data = envelope()
    changed = User.query.filter(User.id == current_user.id, User.vault_check.is_(None)).update(
        {User.vault_check: data["ciphertext"], User.vault_check_nonce: data["nonce"]},
        synchronize_session=False,
    )
    db.session.commit()
    if not changed:
        abort(409)
    log_security_event(current_user.id, "vault_initialized")
    return jsonify(ok=True), 201


@vault_bp.get("")
@login_required
def list_entries():
    entries = (
        VaultEntry.query.filter_by(user_id=current_user.id).order_by(VaultEntry.id.desc()).all()
    )
    return jsonify([dict(id=e.id, ciphertext=e.ciphertext, nonce=e.nonce) for e in entries])


@vault_bp.post("")
@login_required
def create_entry():
    if not current_user.vault_check:
        abort(409)
    data = envelope()
    if data["nonce"] == current_user.vault_check_nonce:
        abort(400)
    entry = VaultEntry(user_id=current_user.id, **data)
    db.session.add(entry)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        abort(409)
    log_security_event(current_user.id, "vault_created", f"entry_id={entry.id}")
    return jsonify(id=entry.id), 201


@vault_bp.delete("/<int:entry_id>")
@login_required
def delete_entry(entry_id):
    entry = VaultEntry.query.filter_by(id=entry_id, user_id=current_user.id).first_or_404()
    db.session.delete(entry)
    db.session.commit()
    log_security_event(current_user.id, "vault_deleted", f"entry_id={entry_id}")
    return "", 204
