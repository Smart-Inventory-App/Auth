"""Tests para POST /auth/login."""
from tests.conftest import register_user, TEST_EMAIL, VALID_PASSWORD


def _login(client, email=TEST_EMAIL, password=VALID_PASSWORD, firebase_token=None):
    body = {"email": email, "password": password}
    if firebase_token is not None:
        body["firebase_token"] = firebase_token
    return client.post("/auth/login", json=body)


def test_login_success_returns_token(client):
    register_user(client)
    r = _login(client)
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_login_wrong_password_returns_401(client):
    register_user(client)
    r = _login(client, password="WrongPass1")
    assert r.status_code == 401
    assert r.json()["detail"] == "auth.invalid_credentials"


def test_login_unknown_email_returns_401(client):
    r = _login(client, email="nobody@example.com")
    assert r.status_code == 401


def test_login_disabled_user_returns_403(client, db):
    register_user(client)
    from app.models.user import User
    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    user.is_active = False
    db.commit()
    r = _login(client)
    assert r.status_code == 403
    assert r.json()["detail"] == "auth.account_disabled"


def test_login_without_firebase_token_succeeds(client):
    # firebase_token es opcional — Android no lo envía
    register_user(client)
    r = client.post("/auth/login", json={"email": TEST_EMAIL, "password": VALID_PASSWORD})
    assert r.status_code == 200


def test_login_with_null_firebase_token_succeeds(client):
    register_user(client)
    r = client.post("/auth/login", json={"email": TEST_EMAIL, "password": VALID_PASSWORD, "firebase_token": None})
    assert r.status_code == 200


def test_login_saves_firebase_token(client, db):
    register_user(client)
    token = "firebase-token-abc123"
    r = _login(client, firebase_token=token)
    assert r.status_code == 200
    from app.models.user import User
    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    assert user.firebase_token == token


def test_login_updates_firebase_token_on_new_device(client, db):
    register_user(client)
    _login(client, firebase_token="old-token")
    _login(client, firebase_token="new-token")
    from app.models.user import User
    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    assert user.firebase_token == "new-token"
