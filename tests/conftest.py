from src.app import create_app
from src.extensions import db
from src.models import User
import pytest
import pyotp
from flask.testing import FlaskClient


class IsolatedClient(FlaskClient):
    def open(self, *args, **kwargs):
        # Keep each request context separate from the test database context.
        with self.application.app_context():
            return super().open(*args, **kwargs)


@pytest.fixture
def app():
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "t" * 32,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "WTF_CSRF_ENABLED": False,
            "RATELIMIT_ENABLED": False,
            "SESSION_COOKIE_SECURE": False,
        }
    )
    app.test_client_class = IsolatedClient
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def register(client):
    def create(username="alice"):
        client.post(
            "/auth/register", data={"username": username, "password": "Strong password 123!"}
        )
        user = User.query.filter_by(username=username).one()
        assert (
            client.post(
                "/auth/two-factor", data={"token": pyotp.TOTP(user.totp_secret).now()}
            ).status_code
            == 302
        )
        return user

    return create
