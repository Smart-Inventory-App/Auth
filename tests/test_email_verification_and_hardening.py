"""Cuentas con contraseña que entran con Google, y endurecimiento de la recuperación de contraseña."""
from sqlalchemy import create_engine

from app import main as main_module
from app.core.config import Settings
from app.core.security import verify_password
from app.models.user import PasswordResetCode, User
from tests.conftest import TEST_EMAIL, VALID_PASSWORD, register_user
from tests.test_google_login import google, id_token, login_google  # noqa: F401 — fixture y helpers
from tests.test_reset_flow import pedir_codigo


def usuario(db):
    db.expire_all()
    return db.query(User).filter(User.email == TEST_EMAIL).first()


# ── cuentas registradas con contraseña que entran con Google ─────────────────

def test_google_conserva_la_contrasena_de_una_cuenta_registrada(client, google, db):
    register_user(client)

    assert login_google(client).status_code == 200

    user = usuario(db)
    assert user.has_password is True
    assert verify_password(VALID_PASSWORD, user.hashed_password)
    # puede seguir entrando con su contraseña de siempre, además de con Google
    r = client.post("/auth/login", json={"email": TEST_EMAIL, "password": VALID_PASSWORD, "firebase_token": None})
    assert r.status_code == 200
    assert client.post("/auth/check-email", json={"email": TEST_EMAIL}).json() == {"exists": True, "password_set": True}
    assert login_google(client).status_code == 200


# ── intentos de verify-code ──────────────────────────────────────────────────

def mal(client, codigo="000000"):
    return client.post("/auth/verify-code", json={"email": TEST_EMAIL, "code": codigo})


def test_un_codigo_incorrecto_suma_un_intento(client, db):
    register_user(client)
    codigo = pedir_codigo(client, db)
    wrong = "111111" if codigo != "111111" else "222222"

    r = mal(client, wrong)

    assert r.status_code == 400
    assert r.json()["detail"] == "auth.invalid_or_expired_code"
    db.expire_all()
    assert db.query(PasswordResetCode).first().failed_attempts == 1


def test_al_quinto_intento_fallido_el_codigo_se_invalida_y_responde_429(client, db):
    register_user(client)
    codigo = pedir_codigo(client, db)
    wrong = "111111" if codigo != "111111" else "222222"

    for _ in range(4):
        assert mal(client, wrong).status_code == 400
    quinto = mal(client, wrong)

    assert quinto.status_code == 429
    assert quinto.json()["detail"] == "auth.too_many_attempts"
    # ni siquiera el código correcto sirve ya: hay que pedir uno nuevo
    r = mal(client, codigo)
    assert r.status_code == 400
    assert r.json()["detail"] == "auth.invalid_or_expired_code"


def test_pedir_un_codigo_nuevo_despues_del_bloqueo_funciona(client, db):
    register_user(client)
    codigo = pedir_codigo(client, db)
    wrong = "111111" if codigo != "111111" else "222222"
    for _ in range(5):
        mal(client, wrong)

    client.post("/auth/forgot-password", json={"email": TEST_EMAIL})
    db.expire_all()
    nuevo = db.query(PasswordResetCode).order_by(PasswordResetCode.created_at.desc()).first().code

    assert client.post("/auth/verify-code", json={"email": TEST_EMAIL, "code": nuevo}).status_code == 200


def test_el_codigo_correcto_sigue_andando_con_intentos_previos(client, db):
    register_user(client)
    codigo = pedir_codigo(client, db)
    wrong = "111111" if codigo != "111111" else "222222"
    for _ in range(3):
        mal(client, wrong)

    assert client.post("/auth/verify-code", json={"email": TEST_EMAIL, "code": codigo}).status_code == 200


def test_sin_codigo_vigente_sigue_siendo_invalid_or_expired(client):
    register_user(client)
    r = mal(client)
    assert r.status_code == 400
    assert r.json()["detail"] == "auth.invalid_or_expired_code"


def test_los_codigos_son_de_seis_digitos(client, db):
    register_user(client)
    for _ in range(5):
        codigo = pedir_codigo(client, db)
        assert len(codigo) == 6 and codigo.isdigit()


# ── DEBUG ────────────────────────────────────────────────────────────────────

def test_debug_viene_apagado_por_defecto(monkeypatch):
    monkeypatch.delenv("DEBUG", raising=False)
    assert Settings(_env_file=None).DEBUG is False


def test_con_debug_apagado_forgot_password_no_devuelve_el_codigo(client, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "DEBUG", False)
    register_user(client)
    r = client.post("/auth/forgot-password", json={"email": TEST_EMAIL})
    assert "debug_code" not in r.json()


def test_con_debug_prendido_forgot_password_devuelve_el_codigo(client, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "DEBUG", True)
    register_user(client)
    r = client.post("/auth/forgot-password", json={"email": TEST_EMAIL})
    assert len(r.json()["debug_code"]) == 6


# ── migración de columnas ────────────────────────────────────────────────────

class FakeConn:
    def __init__(self, log):
        self.log = log

    def execute(self, statement):
        self.log.append(str(statement))


class FakeBegin:
    def __init__(self, log):
        self.log = log

    def __enter__(self):
        return FakeConn(self.log)

    def __exit__(self, *args):
        return False


class FakeBind:
    def __init__(self, dialect, log):
        self.dialect = type("D", (), {"name": dialect})()
        self.log = log

    def begin(self):
        return FakeBegin(self.log)


def test_la_migracion_agrega_todas_las_columnas_nuevas_en_postgres():
    log = []
    main_module.apply_column_migrations(FakeBind("postgresql", log))
    assert log == main_module.COLUMN_MIGRATIONS
    texto = " ".join(log)
    for columna in ("has_password", "failed_attempts"):
        assert f"ADD COLUMN IF NOT EXISTS {columna}" in texto
    assert all("IF NOT EXISTS" in s and "DEFAULT" in s for s in log)


def test_la_migracion_no_hace_nada_fuera_de_postgres():
    log = []
    main_module.apply_column_migrations(FakeBind("sqlite", log))
    assert log == []
    main_module.apply_column_migrations(create_engine("sqlite://"))
