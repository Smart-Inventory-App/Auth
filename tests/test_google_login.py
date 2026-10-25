"""Login con Google: se verifica el idToken (firma, vencimiento, emisor y app para la que fue emitido).

Google se simula con una clave RSA propia: los tokens se firman acá y las claves públicas "de Google" se sirven desde
un httpx.get de mentira.
"""
import time

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk, jwt

from app.core import google as google_module
from app.core.config import settings
from app.models.user import User
from tests.conftest import TEST_EMAIL, VALID_PASSWORD, register_user

CLIENT_ID = "web-client.apps.googleusercontent.com"
OTHER_CLIENT_ID = "otra-app.apps.googleusercontent.com"


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload


def make_key(kid="k1"):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    public_jwk = jwk.construct(public_pem, "RS256").to_dict()
    public_jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return private_pem, public_jwk


KEY_PEM, KEY_JWK = make_key("k1")
OTHER_PEM, _ = make_key("k1")  # otra clave con el mismo nombre: la firma no coincide


def id_token(overrides=None, key=KEY_PEM, kid="k1", algorithm="RS256", drop=()):
    claims = {
        "iss": "https://accounts.google.com",
        "aud": CLIENT_ID,
        "email": TEST_EMAIL,
        "email_verified": True,
        "iat": int(time.time()) - 5,
        "exp": int(time.time()) + 3600,
    }
    claims.update(overrides or {})
    for name in drop:
        claims.pop(name, None)
    return jwt.encode(claims, key, algorithm=algorithm, headers={"kid": kid})


@pytest.fixture
def google(monkeypatch):
    """Configura el client ID y sirve las claves públicas de Google. Cuenta cuántas veces se las pidieron."""
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", CLIENT_ID)
    google_module.reset_certs_cache()
    estado = {"keys": [KEY_JWK], "status": 200, "error": None, "pedidos": 0}

    def fake_get(url, params=None, timeout=None):
        estado["pedidos"] += 1
        assert url == google_module.GOOGLE_CERTS_URL
        if estado["error"]:
            raise estado["error"]
        return FakeResponse({"keys": estado["keys"]}, estado["status"])

    monkeypatch.setattr(google_module.httpx, "get", fake_get)
    yield estado
    google_module.reset_certs_cache()


def login_google(client, token=None):
    return client.post("/auth/google", json={"id_token": token if token is not None else id_token()})


# ── configuración ─────────────────────────────────────────────────────────────

def test_sin_client_id_configurado_el_login_con_google_esta_deshabilitado(client, google, monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "")
    r = login_google(client)
    assert r.status_code == 503
    assert r.json()["detail"] == "auth.google_not_configured"
    assert google["pedidos"] == 0


def test_se_puede_configurar_mas_de_un_client_id(client, google, monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", f" {OTHER_CLIENT_ID} , {CLIENT_ID} ")
    assert login_google(client).status_code == 200


def test_el_token_viejo_con_access_token_ya_no_se_acepta(client, google):
    r = client.post("/auth/google", json={"access_token": "viejo"})
    assert r.status_code == 422


# ── token válido ──────────────────────────────────────────────────────────────

def test_token_valido_crea_el_usuario_si_no_existe(client, google, db):
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


def test_el_emisor_puede_venir_sin_https(client, google):
    assert login_google(client, id_token({"iss": "accounts.google.com"})).status_code == 200


def test_la_audiencia_puede_ser_una_lista_que_incluya_la_app(client, google):
    assert login_google(client, id_token({"aud": [OTHER_CLIENT_ID, CLIENT_ID]})).status_code == 200


def test_acepta_email_verificado_como_texto(client, google):
    assert login_google(client, id_token({"email_verified": "true"})).status_code == 200


# ── token inválido ────────────────────────────────────────────────────────────

def test_un_token_emitido_para_otra_app_es_401(client, google):
    r = login_google(client, id_token({"aud": OTHER_CLIENT_ID}))
    assert r.status_code == 401
    assert r.json()["detail"] == "auth.google_invalid_token"


def test_un_token_sin_audiencia_es_401(client, google):
    assert login_google(client, id_token(drop=("aud",))).status_code == 401


def test_un_token_de_otro_emisor_es_401(client, google):
    r = login_google(client, id_token({"iss": "https://evil.example.com"}))
    assert r.status_code == 401
    assert r.json()["detail"] == "auth.google_invalid_token"


def test_un_token_vencido_es_401(client, google):
    r = login_google(client, id_token({"exp": int(time.time()) - 3600}))
    assert r.status_code == 401
    assert r.json()["detail"] == "auth.google_invalid_token"


def test_un_token_firmado_con_otra_clave_es_401(client, google):
    assert login_google(client, id_token(key=OTHER_PEM)).status_code == 401


def test_un_token_firmado_con_hs256_es_401(client, google):
    # Intento clásico: firmar con HMAC usando la clave pública como secreto
    assert login_google(client, id_token(key="secreto", algorithm="HS256")).status_code == 401


def test_un_texto_que_no_es_un_token_es_401(client, google):
    r = login_google(client, "esto-no-es-un-jwt")
    assert r.status_code == 401
    assert r.json()["detail"] == "auth.google_invalid_token"


def test_con_una_clave_desconocida_pide_las_claves_otra_vez_y_despues_rechaza(client, google):
    r = login_google(client, id_token(kid="nueva"))
    assert r.status_code == 401
    assert google["pedidos"] == 2


def test_si_google_rota_las_claves_el_token_nuevo_se_acepta(client, google):
    login_google(client)
    nueva_pem, nueva_jwk = make_key("k2")
    google["keys"] = [KEY_JWK, nueva_jwk]

    r = login_google(client, id_token(key=nueva_pem, kid="k2"))

    assert r.status_code == 200
    assert google["pedidos"] == 2


def test_las_claves_de_google_se_guardan_en_memoria(client, google):
    login_google(client)
    login_google(client)
    assert google["pedidos"] == 1


def test_pasada_una_hora_se_vuelven_a_pedir_las_claves(client, google, monkeypatch):
    login_google(client)
    ahora = time.time()
    monkeypatch.setattr(google_module.time, "time", lambda: ahora + google_module.CERTS_CACHE_SECONDS + 1)
    login_google(client)
    assert google["pedidos"] == 2


# ── email ─────────────────────────────────────────────────────────────────────

def test_sin_email_es_401(client, google):
    r = login_google(client, id_token(drop=("email",)))
    assert r.status_code == 401
    assert r.json()["detail"] == "auth.google_email_not_verified"


def test_email_no_verificado_es_401(client, google):
    r = login_google(client, id_token({"email_verified": False}))
    assert r.status_code == 401
    assert r.json()["detail"] == "auth.google_email_not_verified"


def test_sin_dato_de_verificacion_es_401(client, google):
    assert login_google(client, id_token(drop=("email_verified",))).status_code == 401


# ── Google no responde ────────────────────────────────────────────────────────

def test_google_inalcanzable_es_503(client, google):
    google["error"] = httpx.RequestError("sin red")
    r = login_google(client)
    assert r.status_code == 503
    assert r.json()["detail"] == "auth.google_unreachable"


def test_google_responde_con_error_es_503(client, google):
    google["status"] = 500
    r = login_google(client)
    assert r.status_code == 503
    assert r.json()["detail"] == "auth.google_unreachable"


# ── cuentas desactivadas ──────────────────────────────────────────────────────

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
