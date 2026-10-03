from functools import wraps

from flask import flash, redirect, url_for
from flask_login import current_user


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            flash("Unauthorized access: administrator privileges required.")
            return redirect(url_for("auth.login"))
        return func(*args, **kwargs)
    return wrapper
