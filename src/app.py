import os
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import click
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from src.config import configuration
from src.extensions import csrf, db, limiter, login_manager
from src.models import User


def create_app(test_config=None):
    load_dotenv()
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(configuration())
    app.config.update(test_config or {})
    if not app.config.get("SECRET_KEY") or len(app.config["SECRET_KEY"]) < 32:
        raise ValueError("Set SECRET_KEY to a random value of at least 32 characters.")
    os.makedirs(app.instance_path, exist_ok=True)
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        try:
            user = db.session.get(User, int(user_id))
        except (ValueError, TypeError):
            return None
        return user if user and user.is_active and user.two_factor_enabled else None

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify(error="Authentication required"), 401
        return redirect(url_for("auth.login"))

    from src.auth.routes import auth_bp
    from src.vault.routes import vault_bp
    from src.admin.routes import admin_bp

    for blueprint in (auth_bp, vault_bp, admin_bp):
        app.register_blueprint(blueprint)

    @app.get("/")
    def index():
        return redirect(url_for("dashboard" if current_user.is_authenticated else "auth.login"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html")

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.cli.command("init-db")
    def init_db():
        db.create_all()
        click.echo("Database initialized (existing tables preserved).")

    @app.cli.command("make-admin")
    @click.argument("username")
    def make_admin(username):
        user = User.query.filter_by(username=username).first()
        if not user:
            raise click.ClickException("Unknown user")
        user.role = "admin"
        db.session.commit()
        click.echo("Administrator role granted.")

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
