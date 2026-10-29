"""
Un administrador da de alta a otro con una contraseña inicial: el nuevo entra con ella y el sistema le pide cambiarla.
"""
import pytest

from app.models.user import User
from tests.conftest import VALID_PASSWORD, admin_token, create_admin, register_user

INITIAL = "Inicial.2026"
NEW = "Definitiva.99"


def headers(email="jefe@x.com"):
    return {"Authorization": f"Bearer {admin_token(email)}"}


def add_admin(client, email="nuevo@x.com", **extra):
    return client.post("/auth/admin/admins", json={"email": email, "full_name": "Nuevo", **extra}, headers=headers())


@pytest.fixture(autouse=True)
def boss(db):
    create_admin(db, email="jefe@x.com")


def login(client, email, password):
    return client.post("/auth/login", json={"email": email, "password": password, "firebase_token": ""})


def test_con_una_contrasena_inicial_se_crea_la_cuenta_ya_lista_para_ingresar(client, db):
    resp = add_admin(client, initial_password=INITIAL)

    assert resp.status_code == 201
    body = resp.json()
    assert body["password_set"] is True
    assert body["invite_token"] is None  # no hace falta el código de invitación
    user = db.query(User).filter(User.email == "nuevo@x.com").one()
    assert user.must_change_password is True and user.has_password is True


def test_la_cuenta_nueva_ingresa_con_la_inicial_y_se_le_avisa_que_tiene_que_cambiarla(client):
    add_admin(client, initial_password=INITIAL)

    resp = login(client, "nuevo@x.com", INITIAL)

    assert resp.status_code == 200 and resp.json()["must_change_password"] is True


def test_el_me_tambien_avisa_que_tiene_que_cambiarla(client):
    add_admin(client, initial_password=INITIAL)
    token = login(client, "nuevo@x.com", INITIAL).json()["access_token"]

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()

    assert me["must_change_password"] is True


@pytest.mark.parametrize(
    "password, code",
    [("Ab1", "auth.password_too_short"), ("abcdefg1", "auth.password_missing_uppercase"),
     ("ABCDEFG1", "auth.password_missing_lowercase"), ("Abcdefgh", "auth.password_missing_digit")],
)
def test_la_contrasena_inicial_cumple_las_reglas_de_siempre(client, db, password, code):
    resp = add_admin(client, initial_password=password)

    assert resp.status_code == 400 and resp.json()["detail"] == code
    assert db.query(User).filter(User.email == "nuevo@x.com").count() == 0


def test_si_el_mail_ya_tiene_cuenta_se_ignora_la_contrasena_inicial_y_se_conserva_la_suya(client, db):
    register_user(client, email="existente@x.com")

    resp = add_admin(client, "existente@x.com", initial_password=INITIAL)

    assert resp.status_code == 201 and resp.json()["password_set"] is True
    assert login(client, "existente@x.com", VALID_PASSWORD).json()["must_change_password"] is False
    assert login(client, "existente@x.com", INITIAL).status_code == 401


def test_sin_contrasena_inicial_sigue_el_camino_de_la_invitacion(client):
    resp = add_admin(client)

    assert resp.json()["password_set"] is False and resp.json()["invite_token"]


def test_una_cuenta_comun_ingresa_sin_la_marca(client):
    register_user(client, email="comun@x.com")

    assert login(client, "comun@x.com", VALID_PASSWORD).json()["must_change_password"] is False


# ── cambiar la contraseña ─────────────────────────────────────────────────────

def session(client):
    add_admin(client, initial_password=INITIAL)
    token = login(client, "nuevo@x.com", INITIAL).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def change(client, auth, current=INITIAL, new=NEW):
    return client.post("/auth/change-password", json={"current_password": current, "new_password": new}, headers=auth)


def test_cambiar_la_contrasena_quita_la_marca_y_la_nueva_es_la_que_vale(client, db):
    auth = session(client)

    assert change(client, auth).status_code == 204

    assert login(client, "nuevo@x.com", INITIAL).status_code == 401
    ok = login(client, "nuevo@x.com", NEW)
    assert ok.status_code == 200 and ok.json()["must_change_password"] is False
    assert client.get("/auth/me", headers=auth).json()["must_change_password"] is False


def test_pide_la_contrasena_actual(client):
    auth = session(client)

    resp = change(client, auth, current="Equivocada.1")

    assert resp.status_code == 400 and resp.json()["detail"] == "auth.invalid_credentials"


def test_la_nueva_no_puede_ser_igual_a_la_actual_ni_incumplir_las_reglas(client):
    auth = session(client)

    same = change(client, auth, new=INITIAL)
    weak = change(client, auth, new="corta")

    assert same.json()["detail"] == "auth.password_same_as_current"
    assert weak.json()["detail"] == "auth.password_too_short"


def test_hace_falta_estar_autenticado(client):
    resp = client.post("/auth/change-password", json={"current_password": INITIAL, "new_password": NEW})

    assert resp.status_code in (401, 403)
