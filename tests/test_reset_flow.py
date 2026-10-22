"""Recorrido completo de recuperación de contraseña, de punta a punta."""
import uuid

from app.core.security import create_reset_token
from app.models.user import PasswordResetCode, User
from tests.conftest import TEST_EMAIL, VALID_PASSWORD, register_user

NUEVA_PASSWORD = "Expelliarmus.9"


def pedir_codigo(client, db, email=TEST_EMAIL) -> str:
    client.post("/auth/forgot-password", json={"email": email})
    user = db.query(User).filter(User.email == email).first()
    return (
        db.query(PasswordResetCode)
        .filter(PasswordResetCode.user_id == user.id)
        .order_by(PasswordResetCode.id.desc())
        .first()
        .code
    )


def test_check_email_reporta_si_existe(client):
    register_user(client)
    assert client.post("/auth/check-email", json={"email": TEST_EMAIL}).json() == {
        "exists": True,
        "password_set": True,
    }


def test_check_email_reporta_si_no_existe(client):
    r = client.post("/auth/check-email", json={"email": "nadie@example.com"})
    assert r.json() == {"exists": False}


def test_verify_code_con_email_desconocido(client):
    r = client.post("/auth/verify-code", json={"email": "nadie@example.com", "code": "123456"})
    assert r.status_code == 400
    assert r.json()["detail"] == "auth.invalid_code"


def test_recuperacion_completa(client, db):
    register_user(client)
    codigo = pedir_codigo(client, db)

    r = client.post("/auth/verify-code", json={"email": TEST_EMAIL, "code": codigo})
    assert r.status_code == 200
    reset_token = r.json()["reset_token"]

    r = client.post("/auth/reset-password",
                    json={"reset_token": reset_token, "new_password": NUEVA_PASSWORD})
    assert r.status_code == 200

    # la contraseña vieja deja de servir y la nueva entra
    vieja = client.post("/auth/login", json={"email": TEST_EMAIL, "password": VALID_PASSWORD,
                                             "firebase_token": None})
    assert vieja.status_code == 401

    nueva = client.post("/auth/login", json={"email": TEST_EMAIL, "password": NUEVA_PASSWORD,
                                             "firebase_token": None})
    assert nueva.status_code == 200
    assert nueva.json()["access_token"]


def test_el_codigo_no_se_puede_reutilizar(client, db):
    register_user(client)
    codigo = pedir_codigo(client, db)

    assert client.post("/auth/verify-code",
                       json={"email": TEST_EMAIL, "code": codigo}).status_code == 200
    segundo = client.post("/auth/verify-code", json={"email": TEST_EMAIL, "code": codigo})
    assert segundo.status_code == 400


def test_reset_con_usuario_borrado(client, db):
    """El token es válido pero el usuario ya no está."""
    token = create_reset_token(str(uuid.uuid4()))
    r = client.post("/auth/reset-password",
                    json={"reset_token": token, "new_password": NUEVA_PASSWORD})
    assert r.status_code == 400
    assert r.json()["detail"] == "auth.invalid_or_expired_token"


def test_reset_con_sub_que_no_es_uuid(client):
    token = create_reset_token("99999")
    r = client.post("/auth/reset-password",
                    json={"reset_token": token, "new_password": NUEVA_PASSWORD})
    assert r.status_code == 400


def _reset_token_de(client, db):
    register_user(client)
    codigo = pedir_codigo(client, db)
    r = client.post("/auth/verify-code", json={"email": TEST_EMAIL, "code": codigo})
    return r.json()["reset_token"]


def test_reset_rechaza_la_misma_contrasena_actual(client, db):
    reset_token = _reset_token_de(client, db)
    r = client.post("/auth/reset-password",
                    json={"reset_token": reset_token, "new_password": VALID_PASSWORD})
    assert r.status_code == 400
    assert r.json()["detail"] == "auth.password_same_as_current"

    # la contraseña no se tocó: la actual sigue entrando
    login = client.post("/auth/login", json={"email": TEST_EMAIL, "password": VALID_PASSWORD,
                                             "firebase_token": None})
    assert login.status_code == 200


def test_check_new_password_distingue_igual_de_distinta(client, db):
    reset_token = _reset_token_de(client, db)

    igual = client.post("/auth/check-new-password",
                        json={"reset_token": reset_token, "new_password": VALID_PASSWORD})
    assert igual.status_code == 200
    assert igual.json() == {"different": False}

    distinta = client.post("/auth/check-new-password",
                           json={"reset_token": reset_token, "new_password": NUEVA_PASSWORD})
    assert distinta.json() == {"different": True}


def test_check_new_password_con_token_invalido(client):
    r = client.post("/auth/check-new-password",
                    json={"reset_token": "invalid.token.here", "new_password": NUEVA_PASSWORD})
    assert r.status_code == 400
    assert r.json()["detail"] == "auth.invalid_or_expired_token"


def test_check_new_password_con_usuario_borrado(client):
    token = create_reset_token(str(uuid.uuid4()))
    r = client.post("/auth/check-new-password",
                    json={"reset_token": token, "new_password": NUEVA_PASSWORD})
    assert r.status_code == 400
    assert r.json()["detail"] == "auth.invalid_or_expired_token"


# ── configurar contraseña por primera vez (cuentas creadas por Google) ────────

EMAIL_GOOGLE = "google@example.com"


def _crear_cuenta_de_google(db, email=EMAIL_GOOGLE) -> User:
    import uuid as uuid_mod
    from app.core.security import hash_password

    user = User(
        id=uuid_mod.uuid4(),
        email=email,
        hashed_password=hash_password(uuid_mod.uuid4().hex),
        has_password=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_check_email_reporta_password_set_en_false_para_cuenta_de_google(client, db):
    _crear_cuenta_de_google(db)
    data = client.post("/auth/check-email", json={"email": EMAIL_GOOGLE}).json()
    assert data == {"exists": True, "password_set": False}


def test_forgot_password_de_cuenta_de_google_manda_el_mail_de_configurar(client, db, monkeypatch):
    _crear_cuenta_de_google(db)
    import app.routes.auth as auth_route

    llamadas = []
    monkeypatch.setattr(auth_route, "send_set_password_code_email",
                        lambda email, code: llamadas.append(("set_password", email)))
    monkeypatch.setattr(auth_route, "send_reset_code_email",
                        lambda email, code: llamadas.append(("reset", email)))

    client.post("/auth/forgot-password", json={"email": EMAIL_GOOGLE})

    assert llamadas == [("set_password", EMAIL_GOOGLE)]


def test_forgot_password_de_cuenta_normal_sigue_mandando_el_mail_de_recuperar(client, monkeypatch):
    register_user(client)
    import app.routes.auth as auth_route

    llamadas = []
    monkeypatch.setattr(auth_route, "send_set_password_code_email",
                        lambda email, code: llamadas.append(("set_password", email)))
    monkeypatch.setattr(auth_route, "send_reset_code_email",
                        lambda email, code: llamadas.append(("reset", email)))

    client.post("/auth/forgot-password", json={"email": TEST_EMAIL})

    assert llamadas == [("reset", TEST_EMAIL)]


def test_configurar_contrasena_de_cuenta_de_google_de_punta_a_punta(client, db):
    _crear_cuenta_de_google(db)
    codigo = pedir_codigo(client, db, email=EMAIL_GOOGLE)

    r = client.post("/auth/verify-code", json={"email": EMAIL_GOOGLE, "code": codigo})
    reset_token = r.json()["reset_token"]

    r = client.post("/auth/reset-password",
                    json={"reset_token": reset_token, "new_password": NUEVA_PASSWORD})
    assert r.status_code == 200

    user = db.query(User).filter(User.email == EMAIL_GOOGLE).first()
    assert user.has_password is True

    # ahora puede loguearse con contraseña, sin pasar por Google
    login = client.post("/auth/login", json={"email": EMAIL_GOOGLE, "password": NUEVA_PASSWORD,
                                             "firebase_token": None})
    assert login.status_code == 200
