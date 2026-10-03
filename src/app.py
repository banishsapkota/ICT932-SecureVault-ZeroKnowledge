from flask import Flask, redirect, render_template, url_for
from flask_login import LoginManager, login_required, current_user

from src.auth.routes import auth_bp
from src.config import Config
from src.extensions import csrf, db, limiter, login_manager
from src.models import User
from src.vault.routes import vault_bp
from src.admin.routes import admin_bp


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config is not None:
        app.config.from_mapping(test_config)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @login_manager.unauthorized_handler
    def unauthorized():
        return redirect(url_for("auth.login"))

    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp, url_prefix="/vault")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    @app.route("/")
    def index():
        return redirect(url_for("auth.login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", user=current_user)

    @app.route("/password-generator")
    @login_required
    def password_generator_page():
        return render_template("password_generator.html")

    with app.app_context():
        db.create_all()

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=False)
