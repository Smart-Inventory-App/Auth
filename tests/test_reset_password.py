"""Tests para forgot-password / verify-code / reset-password."""
import pytest
from datetime import datetime, timedelta
from tests.conftest import register_user, TEST_EMAIL, VALID_PASSWORD


def test_forgot_password_unknown_email_returns_200(client):
    # No revela si el email existe
    r = client.post("/auth/forgot-password", json={"email": "nobody@example.com"})
    assert r.status_code == 200
    assert r.json()["detail"] == "auth.reset_code_sent"


def test_forgot_password_known_email_returns_200(client):
    register_user(client)
    r = client.post("/auth/forgot-password", json={"email": TEST_EMAIL})
    assert r.status_code == 200


def test_verify_code_invalid_returns_400(client):
    register_user(client)
    r = client.post("/auth/verify-code", json={"email": TEST_EMAIL, "code": "000000"})
    assert r.status_code == 400
    assert r.json()["detail"] == "auth.invalid_or_expired_code"


def test_verify_code_valid_returns_reset_token(client, db):
    register_user(client)
    from app.models.user import User, PasswordResetCode
    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    code_obj = PasswordResetCode(
        user_id=user.id,
        code="123456",
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db.add(code_obj)
    db.commit()

    r = client.post("/auth/verify-code", json={"email": TEST_EMAIL, "code": "123456"})
    assert r.status_code == 200
    assert "reset_token" in r.json()


def test_verify_code_expired_returns_400(client, db):
    register_user(client)
    from app.models.user import User, PasswordResetCode
    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    code_obj = PasswordResetCode(
        user_id=user.id,
        code="999999",
        expires_at=datetime.utcnow() - timedelta(minutes=1),  # ya expiró
    )
    db.add(code_obj)
    db.commit()

    r = client.post("/auth/verify-code", json={"email": TEST_EMAIL, "code": "999999"})
    assert r.status_code == 400


def test_reset_password_token_roundtrip():
    # Prueba create/decode sin DB — UUID no compatible con SQLite en el endpoint completo
    from app.core.security import create_reset_token, decode_reset_token
    import uuid
    uid = str(uuid.uuid4())
    token = create_reset_token(uid)
    assert decode_reset_token(token) == uid


def test_reset_password_invalid_token_type_rejected():
    from app.core.security import create_access_token, decode_reset_token
    # Un access token no debe pasar como reset token
    access = create_access_token("some-id", "user@x.com")
    with pytest.raises(ValueError):
        decode_reset_token(access)


def test_reset_password_invalid_token_returns_400(client):
    r = client.post("/auth/reset-password", json={"reset_token": "invalid.token.here", "new_password": "NuevaClave.9"})
    assert r.status_code == 400


def test_reset_password_too_short_returns_400(client, db):
    register_user(client)
    from app.models.user import User
    from app.core.security import create_reset_token
    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    reset_token = create_reset_token(str(user.id))
    r = client.post("/auth/reset-password", json={"reset_token": reset_token, "new_password": "Ab1."})
    assert r.status_code == 400
