# !/usr/bin/env python3
import os
from pathlib import Path

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

from src.config import Config
from src.extensions import db, login_manager, csrf, limiter
from src.models import User


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    if test_config is not None:
        app.config.from_object(test_config)

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @login_manager.unauthorized_handler
    def unauthorized_handler():
        from flask import redirect, url_for
        return redirect(url_for("auth.login"))

    @app.route("/")
    def index():
        from flask import redirect, url_for
        if app.config.get("TESTING"):
            return redirect(url_for("auth.login"))
        return redirect(url_for("auth.login"))

    from src.auth.routes import auth_bp
    from src.vault.routes import vault_bp
    from src.admin.routes import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp, url_prefix="/vault")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    with app.app_context():
        db.create_all()

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=False)
