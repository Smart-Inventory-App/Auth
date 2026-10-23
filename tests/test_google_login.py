"""Tests del login con Google, con la llamada a Google simulada."""
import httpx
import pytest

from app.models.user import User
from app.routes import auth as auth_route
from tests.conftest import TEST_EMAIL, VALID_PASSWORD, register_user


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload


@pytest.fixture
def google(monkeypatch):
    """Sustituye httpx.get por una respuesta configurable."""
    estado = {"payload": {"email": TEST_EMAIL, "verified_email": True}, "status": 200,
              "error": None}

    def fake_get(url, params=None, timeout=None):
        if estado["error"]:
            raise estado["error"]
        return FakeResponse(estado["payload"], estado["status"])

    monkeypatch.setattr(auth_route.httpx, "get", fake_get)
    return estado


def login_google(client, token="tok"):
    return client.post("/auth/google", json={"access_token": token})


def test_google_inalcanzable_es_503(client, google):
    google["error"] = httpx.RequestError("sin red")
    r = login_google(client)
    assert r.status_code == 503
    assert r.json()["detail"] == "auth.google_unreachable"


def test_token_rechazado_por_google_es_401(client, google):
    google["status"] = 401
    r = login_google(client)
    assert r.status_code == 401
    assert r.json()["detail"] == "auth.google_invalid_token"


def test_sin_email_es_401(client, google):
    google["payload"] = {"verified_email": True}
    assert login_google(client).json()["detail"] == "auth.google_email_not_verified"


def test_email_no_verificado_es_401(client, google):
    google["payload"] = {"email": TEST_EMAIL, "verified_email": False}
    assert login_google(client).json()["detail"] == "auth.google_email_not_verified"


def test_crea_el_usuario_si_no_existe(client, google, db):
    r = login_google(client)
    assert r.status_code == 200
    assert r.json()["access_token"]
    assert db.query(User).filter(User.email == TEST_EMAIL).first() is not None


def test_reutiliza_el_usuario_existente(client, google, db):
    register_user(client)
    login_google(client)
    assert db.query(User).filter(User.email == TEST_EMAIL).count() == 1


def test_cuenta_creada_por_google_no_tiene_contrasena_propia(client, google, db):
    login_google(client)
    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    assert user.has_password is False


def test_reutilizar_cuenta_existente_no_le_toca_has_password(client, google, db):
    register_user(client)
    login_google(client)
    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    assert user.has_password is True


def test_usuario_desactivado_es_403(client, google, db):
    register_user(client)
    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    user.is_active = False
    db.commit()

    r = login_google(client)
    assert r.status_code == 403
    assert r.json()["detail"] == "auth.account_disabled"


def test_login_normal_de_usuario_desactivado_es_403(client, db):
    register_user(client)
    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    user.is_active = False
    db.commit()

    r = client.post("/auth/login", json={"email": TEST_EMAIL, "password": VALID_PASSWORD,
                                         "firebase_token": None})
    assert r.status_code == 403
    assert r.json()["detail"] == "auth.account_disabled"
