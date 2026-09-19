"""Tests de /auth/me y del registro del token de Firebase."""
import uuid

from jose import jwt

from app.core.config import settings
from app.models.user import User
from tests.conftest import TEST_EMAIL, VALID_PASSWORD, register_user


def login(client, email=TEST_EMAIL, password=VALID_PASSWORD) -> str:
    register_user(client, email, password)
    r = client.post("/auth/login", json={"email": email, "password": password,
                                         "firebase_token": None})
    return r.json()["access_token"]


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def token_para(user_id: str) -> str:
    return jwt.encode({"sub": user_id}, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


INEXISTENTE = str(uuid.uuid4())


# --- /auth/me ---

def test_me_sin_credenciales(client):
    assert client.get("/auth/me").status_code in (401, 403)


def test_me_con_token_invalido(client):
    assert client.get("/auth/me", headers=bearer("basura")).status_code == 401


def test_me_con_usuario_inexistente(client):
    r = client.get("/auth/me", headers=bearer(token_para(INEXISTENTE)))
    assert r.status_code == 401
    assert r.json()["detail"] == "auth.user_not_found"


def test_me_con_sub_que_no_es_uuid(client):
    r = client.get("/auth/me", headers=bearer(token_para("99999")))
    assert r.status_code == 401
    assert r.json()["detail"] == "auth.invalid_token"


def test_me_devuelve_id_y_email(client):
    token = login(client)
    body = client.get("/auth/me", headers=bearer(token)).json()
    assert body["email"] == TEST_EMAIL
    assert body["id"]


# --- PATCH /auth/firebase-token ---

def test_firebase_token_sin_credenciales(client):
    r = client.patch("/auth/firebase-token", json={"firebase_token": "x"})
    assert r.status_code in (401, 403)


def test_firebase_token_con_jwt_invalido(client):
    r = client.patch("/auth/firebase-token", json={"firebase_token": "x"},
                     headers=bearer("basura"))
    assert r.status_code == 401


def test_firebase_token_usuario_inexistente(client):
    r = client.patch("/auth/firebase-token", json={"firebase_token": "x"},
                     headers=bearer(token_para(INEXISTENTE)))
    assert r.status_code == 401
    assert r.json()["detail"] == "auth.user_not_found"


def test_firebase_token_se_guarda(client, db):
    token = login(client)
    r = client.patch("/auth/firebase-token", json={"firebase_token": "fcm-abc"},
                     headers=bearer(token))
    assert r.status_code == 204

    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    assert user.firebase_token == "fcm-abc"


def test_firebase_token_se_actualiza_si_cambia(client, db):
    token = login(client)
    client.patch("/auth/firebase-token", json={"firebase_token": "viejo"}, headers=bearer(token))
    client.patch("/auth/firebase-token", json={"firebase_token": "nuevo"}, headers=bearer(token))

    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    assert user.firebase_token == "nuevo"


def test_login_registra_el_token_de_firebase(client, db):
    register_user(client)
    client.post("/auth/login", json={"email": TEST_EMAIL, "password": VALID_PASSWORD,
                                     "firebase_token": "desde-login"})
    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    assert user.firebase_token == "desde-login"


def test_login_sin_token_no_borra_el_existente(client, db):
    register_user(client)
    client.post("/auth/login", json={"email": TEST_EMAIL, "password": VALID_PASSWORD,
                                     "firebase_token": "previo"})
    client.post("/auth/login", json={"email": TEST_EMAIL, "password": VALID_PASSWORD,
                                     "firebase_token": None})

    user = db.query(User).filter(User.email == TEST_EMAIL).first()
    assert user.firebase_token == "previo"
