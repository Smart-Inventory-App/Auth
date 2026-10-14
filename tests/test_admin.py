"""Tests para /auth/admin/* (whitelist de administradores)."""
from datetime import datetime, timedelta

import pytest
from jose import jwt

from app.core.config import settings
from app.core.security import create_admin_invite_token, create_reset_token
from tests.conftest import TEST_EMAIL, VALID_PASSWORD, admin_token, create_admin, register_user

INTERNAL_TOKEN = "token-interno-de-prueba"
INTERNAL = {"X-Internal-Token": INTERNAL_TOKEN}


@pytest.fixture
def internal_token(monkeypatch):
    monkeypatch.setattr(settings, "INTERNAL_SERVICE_TOKEN", INTERNAL_TOKEN)


def invite(email):
    return create_admin_invite_token(email)


def set_password(client, email, password=VALID_PASSWORD, invite_token=None):
    return client.post(
        "/auth/admin/set-password",
        json={"email": email, "password": password, "invite_token": invite_token or invite(email)},
    )


# ── check ────────────────────────────────────────────────────────────────────

def test_check_reconoce_un_admin_activo(client, db):
    create_admin(db, email="admin@x.com", password_set=True)

    data = client.post("/auth/admin/check", json={"email": "admin@x.com"}).json()

    assert data == {"exists": True, "is_admin": True, "password_set": True, "full_name": None}


def test_check_reconoce_un_usuario_de_la_app_sin_ser_admin(client, db):
    register_user(client, email="user@x.com")

    data = client.post("/auth/admin/check", json={"email": "user@x.com"}).json()

    assert data == {"exists": True, "is_admin": False, "password_set": True, "full_name": None}


def test_check_un_email_desconocido_no_existe(client):
    data = client.post("/auth/admin/check", json={"email": "nadie@x.com"}).json()

    assert data == {"exists": False, "is_admin": False, "password_set": False, "full_name": None}


def test_check_un_admin_inactivo_no_cuenta_como_admin(client, db):
    create_admin(db, email="baja@x.com", is_active=False)

    data = client.post("/auth/admin/check", json={"email": "baja@x.com"}).json()

    assert data["is_admin"] is False


# ── set-password ─────────────────────────────────────────────────────────────

def test_set_password_crea_el_usuario_y_marca_al_admin(client, db):
    create_admin(db, email="nuevo@x.com", password_set=False)

    resp = set_password(client, "nuevo@x.com")

    assert resp.status_code == 204
    from app.models.admin import AdminUser
    from app.models.user import User
    admin = db.query(AdminUser).filter(AdminUser.email == "nuevo@x.com").one()
    assert admin.password_set is True
    assert db.query(User).filter(User.email == "nuevo@x.com").one()


def test_set_password_ya_definida_es_conflicto(client, db):
    create_admin(db, email="ya@x.com", password_set=True)

    resp = set_password(client, "ya@x.com")

    assert resp.status_code == 409


def test_set_password_de_un_email_que_no_es_admin_es_403(client):
    resp = set_password(client, "nadie@x.com")

    assert resp.status_code == 403


def test_set_password_de_un_email_que_ya_tenia_cuenta_reemplaza_la_contrasena(client, db):
    from app.models.admin import AdminUser

    register_user(client, email="repetido@x.com", password="Anterior.123")
    create_admin(db, email="repetido@x.com", password_set=False)

    resp = set_password(client, "repetido@x.com", password="Nueva.Clave9")

    assert resp.status_code == 204
    assert db.query(AdminUser).filter(AdminUser.email == "repetido@x.com").one().password_set is True
    assert client.post("/auth/admin/login", json={"email": "repetido@x.com", "password": "Nueva.Clave9"}).status_code == 200
    assert client.post("/auth/admin/login", json={"email": "repetido@x.com", "password": "Anterior.123"}).status_code == 401


def test_quien_registro_antes_el_email_de_un_admin_pendiente_no_hereda_el_rol(client, db):
    from app.models.user import User

    create_admin(db, email="squat@x.com", password_set=False)
    client.post("/auth/register", json={"email": "squat@x.com", "password": "Atacante.1"})

    assert set_password(client, "squat@x.com", password="Duenio.2024").status_code == 204

    assert client.post("/auth/admin/login", json={"email": "squat@x.com", "password": "Atacante.1"}).status_code == 401
    assert client.post("/auth/admin/login", json={"email": "squat@x.com", "password": "Duenio.2024"}).status_code == 200
    assert db.query(User).filter(User.email == "squat@x.com").count() == 1


def test_sin_el_codigo_no_se_puede_pisar_la_contrasena_de_una_cuenta_existente(client, db):
    register_user(client, email="victima@x.com", password="Original.123")
    create_admin(db, email="victima@x.com", password_set=False)

    resp = client.post(
        "/auth/admin/set-password",
        json={"email": "victima@x.com", "password": "Atacante.1", "invite_token": "basura"},
    )

    assert resp.status_code == 403
    assert client.post("/auth/login", json={"email": "victima@x.com", "password": "Original.123"}).status_code == 200


def test_set_password_de_una_cuenta_deshabilitada_no_la_reactiva(client, db):
    from app.models.user import User

    register_user(client, email="baja@x.com")
    create_admin(db, email="baja@x.com", password_set=False)
    db.query(User).filter(User.email == "baja@x.com").update({"is_active": False})
    db.commit()

    assert set_password(client, "baja@x.com", password="Nueva.Clave9").status_code == 204

    resp = client.post("/auth/admin/login", json={"email": "baja@x.com", "password": "Nueva.Clave9"})
    assert resp.status_code == 403
    assert resp.json()["detail"] == "auth.account_disabled"


def test_set_password_muy_corta_es_400(client, db):
    create_admin(db, email="corta@x.com", password_set=False)

    resp = set_password(client, "corta@x.com", password="abc1")

    assert resp.status_code == 400


# ── login ────────────────────────────────────────────────────────────────────

def test_login_exitoso_de_un_admin_devuelve_token(client, db):
    create_admin(db, email="admin@x.com", password_set=True)
    register_user(client, email="admin@x.com")

    resp = client.post("/auth/admin/login", json={"email": "admin@x.com", "password": VALID_PASSWORD})

    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_admin_sin_contrasena_definida_es_conflicto(client, db):
    create_admin(db, email="sinpass@x.com", password_set=False)

    resp = client.post("/auth/admin/login", json={"email": "sinpass@x.com", "password": "x"})

    assert resp.status_code == 409


def test_login_admin_inactivo_es_403(client, db):
    create_admin(db, email="baja@x.com", is_active=False, password_set=True)

    resp = client.post("/auth/admin/login", json={"email": "baja@x.com", "password": "x"})

    assert resp.status_code == 403


def test_login_cuenta_desconocida_es_403(client):
    resp = client.post("/auth/admin/login", json={"email": "nadie@x.com", "password": "x"})

    assert resp.status_code == 403


def test_login_credenciales_invalidas(client, db):
    create_admin(db, email="admin@x.com", password_set=True)
    register_user(client, email="admin@x.com")

    resp = client.post("/auth/admin/login", json={"email": "admin@x.com", "password": "mal-password"})

    assert resp.status_code == 401


# ── whitelist ────────────────────────────────────────────────────────────────

def test_whitelist_de_un_admin_activo(client, db, internal_token):
    create_admin(db, email="admin@x.com", full_name="Ana", password_set=True)

    data = client.get("/auth/admin/whitelist", params={"email": "admin@x.com"}, headers=INTERNAL).json()

    assert data == {"is_admin": True, "is_active": True, "password_set": True, "full_name": "Ana"}


def test_whitelist_de_un_admin_inactivo_sigue_marcando_is_admin(client, db, internal_token):
    create_admin(db, email="baja@x.com", is_active=False, password_set=True)

    data = client.get("/auth/admin/whitelist", params={"email": "baja@x.com"}, headers=INTERNAL).json()

    assert data["is_admin"] is True
    assert data["is_active"] is False


def test_whitelist_de_un_email_que_no_es_admin(client, internal_token):
    data = client.get("/auth/admin/whitelist", params={"email": "nadie@x.com"}, headers=INTERNAL).json()

    assert data == {"is_admin": False, "is_active": False, "password_set": False, "full_name": None}


# ── admins ───────────────────────────────────────────────────────────────────

def test_list_admins_requiere_ser_admin(client):
    resp = client.get("/auth/admin/admins")

    assert resp.status_code in (401, 403)


def test_list_admins_los_devuelve(client, db):
    create_admin(db, email="jefe@x.com")
    create_admin(db, email="viejo@x.com")
    token = admin_token("jefe@x.com")

    resp = client.get("/auth/admin/admins", headers={"Authorization": f"Bearer {token}"})

    emails = [a["email"] for a in resp.json()]
    assert "jefe@x.com" in emails
    assert "viejo@x.com" in emails


def test_create_admin_de_un_email_nuevo(client, db):
    create_admin(db, email="jefe@x.com")
    token = admin_token("jefe@x.com")

    resp = client.post(
        "/auth/admin/admins",
        json={"email": "flamante@x.com", "full_name": "Flamante"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 201
    assert resp.json()["password_set"] is False


def test_create_admin_de_un_usuario_que_ya_existe_hereda_password_set(client, db):
    create_admin(db, email="jefe@x.com")
    register_user(client, email="promovido@x.com")
    token = admin_token("jefe@x.com")

    resp = client.post(
        "/auth/admin/admins",
        json={"email": "promovido@x.com"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 201
    assert resp.json()["password_set"] is True


def test_create_admin_ya_existente_es_conflicto(client, db):
    create_admin(db, email="jefe@x.com")
    create_admin(db, email="repe@x.com")
    token = admin_token("jefe@x.com")

    resp = client.post(
        "/auth/admin/admins",
        json={"email": "repe@x.com"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 409


# ── set-password: reglas de contraseña ───────────────────────────────────────

import pytest


@pytest.mark.parametrize("password, detail", [
    ("sinmayuscula1", "auth.password_missing_uppercase"),
    ("SINMINUSCULA1", "auth.password_missing_lowercase"),
    ("SinNumeroAlguno", "auth.password_missing_digit"),
])
def test_set_password_exige_mayuscula_minuscula_y_numero(client, db, password, detail):
    create_admin(db, email="reglas@x.com", password_set=False)

    resp = set_password(client, "reglas@x.com", password=password)

    assert resp.status_code == 400
    assert resp.json()["detail"] == detail


def test_set_password_rechazada_no_crea_la_cuenta_ni_marca_al_admin(client, db):
    from app.models.admin import AdminUser
    from app.models.user import User

    create_admin(db, email="intacto@x.com", password_set=False)

    resp = set_password(client, "intacto@x.com", password="corta1A")

    assert resp.status_code == 400

    assert db.query(User).filter(User.email == "intacto@x.com").count() == 0
    assert db.query(AdminUser).filter(AdminUser.email == "intacto@x.com").one().password_set is False


# ── login: cuenta en la whitelist pero sin usuario, o deshabilitada ───────────

def test_login_de_un_admin_con_password_set_pero_sin_usuario_es_401(client, db):
    create_admin(db, email="huerfano@x.com", password_set=True)

    resp = client.post("/auth/admin/login", json={"email": "huerfano@x.com", "password": VALID_PASSWORD})

    assert resp.status_code == 401
    assert resp.json()["detail"] == "auth.invalid_credentials"


def test_login_de_un_admin_cuya_cuenta_esta_deshabilitada_es_403(client, db):
    from app.models.user import User

    register_user(client, email="deshab@x.com")
    create_admin(db, email="deshab@x.com", password_set=True)
    db.query(User).filter(User.email == "deshab@x.com").update({"is_active": False})
    db.commit()

    resp = client.post("/auth/admin/login", json={"email": "deshab@x.com", "password": VALID_PASSWORD})

    assert resp.status_code == 403
    assert resp.json()["detail"] == "auth.account_disabled"


# ── get_current_admin: tokens que no sirven ───────────────────────────────────

def test_un_token_sin_email_no_sirve_para_listar_admins(client):
    from jose import jwt

    from app.core.config import settings

    token = jwt.encode({"sub": "1"}, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    resp = client.get("/auth/admin/admins", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 401
    assert resp.json()["detail"] == "auth.invalid_token"


def test_un_token_firmado_con_otro_secreto_es_401(client):
    from jose import jwt

    token = jwt.encode({"email": "admin@x.com"}, "otro-secreto", algorithm="HS256")

    resp = client.get("/auth/admin/admins", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 401


def test_un_token_de_reseteo_de_contrasena_no_sirve_como_token_de_admin(client, db):
    from app.core.security import create_reset_token

    create_admin(db, email="admin@x.com", password_set=True)

    resp = client.get("/auth/admin/admins", headers={"Authorization": f"Bearer {create_reset_token('1')}"})

    assert resp.status_code == 401


def test_un_token_valido_de_un_email_que_no_es_admin_es_403(client):
    resp = client.get("/auth/admin/admins", headers={"Authorization": f"Bearer {admin_token('comun@x.com')}"})

    assert resp.status_code == 403
    assert resp.json()["detail"] == "auth.not_an_admin"


def test_un_token_de_un_admin_dado_de_baja_es_403(client, db):
    create_admin(db, email="baja@x.com", is_active=False, password_set=True)

    resp = client.get("/auth/admin/admins", headers={"Authorization": f"Bearer {admin_token('baja@x.com')}"})

    assert resp.status_code == 403


def test_crear_admin_sin_token_es_403(client):
    resp = client.post("/auth/admin/admins", json={"email": "nuevo@x.com"})

    assert resp.status_code in (401, 403)


# ── set-password: el código de invitación ────────────────────────────────────

def test_set_password_sin_codigo_de_invitacion_es_422(client, db):
    create_admin(db, email="pend@x.com", password_set=False)

    resp = client.post("/auth/admin/set-password", json={"email": "pend@x.com", "password": VALID_PASSWORD})

    assert resp.status_code == 422


def test_un_tercero_sin_codigo_no_puede_quedarse_con_un_admin_pendiente(client, db):
    from app.models.admin import AdminUser
    from app.models.user import User

    create_admin(db, email="victima@x.com", password_set=False)

    for token in ["", "no-es-un-jwt", invite("otro@x.com")]:
        resp = client.post(
            "/auth/admin/set-password",
            json={"email": "victima@x.com", "password": "Atacante.1", "invite_token": token},
        )
        assert resp.status_code == 403
        assert resp.json()["detail"] == "auth.invalid_invite"

    assert db.query(User).filter(User.email == "victima@x.com").count() == 0
    assert db.query(AdminUser).filter(AdminUser.email == "victima@x.com").one().password_set is False
    assert client.post("/auth/admin/login", json={"email": "victima@x.com", "password": "Atacante.1"}).status_code == 409


def test_el_codigo_de_otro_email_no_sirve(client, db):
    create_admin(db, email="a@x.com", password_set=False)
    create_admin(db, email="b@x.com", password_set=False)

    resp = set_password(client, "a@x.com", invite_token=invite("b@x.com"))

    assert resp.status_code == 403
    assert resp.json()["detail"] == "auth.invalid_invite"


def test_un_codigo_vencido_no_sirve(client, db):
    create_admin(db, email="tarde@x.com", password_set=False)
    vencido = jwt.encode(
        {"invite_for": "tarde@x.com", "type": "admin_invite", "exp": datetime.utcnow() - timedelta(minutes=1)},
        settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM,
    )

    resp = set_password(client, "tarde@x.com", invite_token=vencido)

    assert resp.status_code == 403
    assert resp.json()["detail"] == "auth.invalid_invite"


def test_un_codigo_firmado_con_otro_secreto_no_sirve(client, db):
    create_admin(db, email="falso@x.com", password_set=False)
    falso = jwt.encode(
        {"invite_for": "falso@x.com", "type": "admin_invite", "exp": datetime.utcnow() + timedelta(hours=1)},
        "otro-secreto", algorithm="HS256",
    )

    assert set_password(client, "falso@x.com", invite_token=falso).status_code == 403


@pytest.mark.parametrize("make", [
    lambda email: admin_token(email),
    lambda email: create_reset_token("1"),
    lambda email: jwt.encode({"invite_for": email, "exp": datetime.utcnow() + timedelta(hours=1)},
                             settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM),
], ids=["token-de-acceso", "token-de-reseteo", "sin-type"])
def test_otros_tokens_no_sirven_como_codigo_de_invitacion(client, db, make):
    create_admin(db, email="otro@x.com", password_set=False)

    resp = set_password(client, "otro@x.com", invite_token=make("otro@x.com"))

    assert resp.status_code == 403


def test_el_codigo_solo_sirve_una_vez(client, db):
    create_admin(db, email="unavez@x.com", password_set=False)
    codigo = invite("unavez@x.com")

    assert set_password(client, "unavez@x.com", invite_token=codigo).status_code == 204
    segunda = set_password(client, "unavez@x.com", password="Otra.Clave9", invite_token=codigo)

    assert segunda.status_code == 409
    assert segunda.json()["detail"] == "auth.password_already_set"
    assert client.post("/auth/admin/login", json={"email": "unavez@x.com", "password": VALID_PASSWORD}).status_code == 200


def test_con_codigo_valido_un_email_inexistente_en_la_whitelist_es_403(client):
    resp = set_password(client, "fantasma@x.com")

    assert resp.status_code == 403
    assert resp.json()["detail"] == "auth.not_an_admin"


def test_el_codigo_de_invitacion_no_sirve_como_token_de_admin(client, db):
    create_admin(db, email="jefe@x.com", password_set=True)

    resp = client.get("/auth/admin/admins", headers={"Authorization": f"Bearer {invite('jefe@x.com')}"})

    assert resp.status_code == 401


def test_el_codigo_de_invitacion_no_es_un_token_de_acceso_para_otros_servicios():
    payload = jwt.decode(invite("x@x.com"), settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])

    assert "sub" not in payload and "email" not in payload


# ── alta de admin: entrega del código ────────────────────────────────────────

def test_create_admin_de_un_email_nuevo_devuelve_el_codigo_y_con_el_define_su_clave(client, db):
    create_admin(db, email="jefe@x.com")

    resp = client.post(
        "/auth/admin/admins",
        json={"email": "flamante@x.com", "full_name": "Flamante"},
        headers={"Authorization": f"Bearer {admin_token('jefe@x.com')}"},
    )

    codigo = resp.json()["invite_token"]
    assert codigo
    assert set_password(client, "flamante@x.com", invite_token=codigo).status_code == 204
    assert client.post("/auth/admin/login", json={"email": "flamante@x.com", "password": VALID_PASSWORD}).status_code == 200


def test_create_admin_de_un_usuario_existente_no_devuelve_codigo(client, db):
    create_admin(db, email="jefe@x.com")
    register_user(client, email="promovido@x.com")

    resp = client.post(
        "/auth/admin/admins",
        json={"email": "promovido@x.com"},
        headers={"Authorization": f"Bearer {admin_token('jefe@x.com')}"},
    )

    assert resp.json()["invite_token"] is None


def test_el_codigo_no_se_guarda_ni_se_vuelve_a_mostrar(client, db):
    create_admin(db, email="jefe@x.com")
    headers = {"Authorization": f"Bearer {admin_token('jefe@x.com')}"}
    client.post("/auth/admin/admins", json={"email": "nuevo@x.com"}, headers=headers)

    listado = client.get("/auth/admin/admins", headers=headers).json()

    assert all(a["invite_token"] is None for a in listado)


# ── endpoints públicos / internos: qué exponen ───────────────────────────────

def test_check_no_expone_el_nombre_del_admin(client, db):
    create_admin(db, email="ana@x.com", full_name="Ana Admin", password_set=True)

    data = client.post("/auth/admin/check", json={"email": "ana@x.com"}).json()

    assert data["is_admin"] is True
    assert data["full_name"] is None


def test_whitelist_sin_token_interno_es_403(client, db, internal_token):
    create_admin(db, email="admin@x.com", full_name="Ana", password_set=True)

    resp = client.get("/auth/admin/whitelist", params={"email": "admin@x.com"})

    assert resp.status_code == 403
    assert "Ana" not in resp.text


def test_whitelist_con_token_interno_incorrecto_es_403(client, db, internal_token):
    resp = client.get("/auth/admin/whitelist", params={"email": "a@x.com"}, headers={"X-Internal-Token": "incorrecto"})

    assert resp.status_code == 403


def test_whitelist_con_un_jwt_de_usuario_no_alcanza(client, db, internal_token):
    create_admin(db, email="admin@x.com", password_set=True)

    resp = client.get(
        "/auth/admin/whitelist", params={"email": "admin@x.com"},
        headers={"Authorization": f"Bearer {admin_token('admin@x.com')}"},
    )

    assert resp.status_code == 403


def test_whitelist_queda_cerrada_si_el_servicio_no_tiene_token_interno(client, db, monkeypatch):
    monkeypatch.setattr(settings, "INTERNAL_SERVICE_TOKEN", "")
    create_admin(db, email="admin@x.com", password_set=True)

    vacio = client.get("/auth/admin/whitelist", params={"email": "admin@x.com"}, headers={"X-Internal-Token": ""})
    sin_header = client.get("/auth/admin/whitelist", params={"email": "admin@x.com"})

    assert vacio.status_code == 403
    assert sin_header.status_code == 403
