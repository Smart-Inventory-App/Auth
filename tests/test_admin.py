"""Tests para /auth/admin/* (whitelist de administradores)."""
from tests.conftest import TEST_EMAIL, VALID_PASSWORD, admin_token, create_admin, register_user


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

    resp = client.post("/auth/admin/set-password", json={"email": "nuevo@x.com", "password": VALID_PASSWORD})

    assert resp.status_code == 204
    from app.models.admin import AdminUser
    from app.models.user import User
    admin = db.query(AdminUser).filter(AdminUser.email == "nuevo@x.com").one()
    assert admin.password_set is True
    assert db.query(User).filter(User.email == "nuevo@x.com").one()


def test_set_password_ya_definida_es_conflicto(client, db):
    create_admin(db, email="ya@x.com", password_set=True)

    resp = client.post("/auth/admin/set-password", json={"email": "ya@x.com", "password": VALID_PASSWORD})

    assert resp.status_code == 409


def test_set_password_de_un_email_que_no_es_admin_es_403(client):
    resp = client.post("/auth/admin/set-password", json={"email": "nadie@x.com", "password": VALID_PASSWORD})

    assert resp.status_code == 403


def test_set_password_email_ya_registrado_en_auth_se_da_por_valido(client, db):
    register_user(client, email="repetido@x.com")
    create_admin(db, email="repetido@x.com", password_set=False)

    resp = client.post("/auth/admin/set-password", json={"email": "repetido@x.com", "password": VALID_PASSWORD})

    assert resp.status_code == 409
    assert resp.json()["detail"] == "auth.email_already_registered"
    from app.models.admin import AdminUser
    admin = db.query(AdminUser).filter(AdminUser.email == "repetido@x.com").one()
    assert admin.password_set is True


def test_set_password_muy_corta_es_400(client, db):
    create_admin(db, email="corta@x.com", password_set=False)

    resp = client.post("/auth/admin/set-password", json={"email": "corta@x.com", "password": "abc1"})

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

def test_whitelist_de_un_admin_activo(client, db):
    create_admin(db, email="admin@x.com", full_name="Ana", password_set=True)

    data = client.get("/auth/admin/whitelist", params={"email": "admin@x.com"}).json()

    assert data == {"is_admin": True, "is_active": True, "password_set": True, "full_name": "Ana"}


def test_whitelist_de_un_admin_inactivo_sigue_marcando_is_admin(client, db):
    create_admin(db, email="baja@x.com", is_active=False, password_set=True)

    data = client.get("/auth/admin/whitelist", params={"email": "baja@x.com"}).json()

    assert data["is_admin"] is True
    assert data["is_active"] is False


def test_whitelist_de_un_email_que_no_es_admin(client):
    data = client.get("/auth/admin/whitelist", params={"email": "nadie@x.com"}).json()

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
