"""`create_admin.py`: alta por línea de comandos del primer admin."""
import sys

import pytest

import create_admin as script
from app.core.security import decode_admin_invite_token
from app.models.admin import AdminUser
from tests.conftest import TestingSession, engine, create_admin


@pytest.fixture(autouse=True)
def script_db(monkeypatch):
    monkeypatch.setattr(script, "SessionLocal", TestingSession)
    monkeypatch.setattr(script, "engine", engine)


def run(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["create_admin.py", *args])
    script.main()
    return capsys.readouterr().out


def codigo_de(output):
    return output.strip().splitlines()[-1]


def test_agrega_a_la_whitelist_e_imprime_un_codigo_valido_para_ese_email(monkeypatch, capsys, db):
    out = run(monkeypatch, capsys, "nuevo@x.com", "Nuevo Admin")

    admin = db.query(AdminUser).filter(AdminUser.email == "nuevo@x.com").one()
    assert admin.full_name == "Nuevo Admin"
    assert admin.password_set is False
    assert decode_admin_invite_token(codigo_de(out)) == "nuevo@x.com"


def test_sin_argumentos_crea_el_admin_por_defecto(monkeypatch, capsys, db):
    out = run(monkeypatch, capsys)

    assert "admin por defecto" in out
    assert db.query(AdminUser).filter(AdminUser.email == "admin@smartinventory.com").count() == 1


def test_si_sigue_pendiente_reimprime_un_codigo_nuevo_sin_duplicar(monkeypatch, capsys, db):
    create_admin(db, email="pend@x.com", password_set=False)

    out = run(monkeypatch, capsys, "pend@x.com")

    assert "sigue pendiente" in out
    assert decode_admin_invite_token(codigo_de(out)) == "pend@x.com"
    assert db.query(AdminUser).filter(AdminUser.email == "pend@x.com").count() == 1


def test_si_ya_definio_su_contrasena_no_imprime_ningun_codigo(monkeypatch, capsys, db):
    create_admin(db, email="listo@x.com", password_set=True)

    out = run(monkeypatch, capsys, "listo@x.com")

    assert "No se creó nada" in out
    assert "Código de invitación" not in out
