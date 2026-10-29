"""Al crear la cuenta con Google, el perfil nuevo arranca con el nombre y el apellido de la cuenta de Google (y solo ahí)."""
import pytest
from sqlalchemy import text

from app.core.profile_seed import NAME_MAX, names_from_claims, seed_profile_names
from tests.conftest import TEST_EMAIL, register_user
from tests.test_google_login import google, id_token, login_google  # noqa: F401  (el fixture simula a Google)


@pytest.fixture
def profiles(db):
    """La tabla `user_profiles`, que crea `app_backend` y la que comparten los servicios."""
    db.execute(text("CREATE TABLE user_profiles (user_id VARCHAR PRIMARY KEY, first_name VARCHAR, last_name VARCHAR)"))
    db.commit()
    yield
    db.execute(text("DROP TABLE IF EXISTS user_profiles"))
    db.commit()


def profile_of(db, email=TEST_EMAIL):
    user_id = str(db.execute(text("SELECT id FROM auth_users WHERE email = :e"), {"e": email}).scalar()).replace("-", "")
    rows = db.execute(text("SELECT user_id, first_name, last_name FROM user_profiles")).all()
    return next(((first, last) for uid, first, last in rows if uid.replace("-", "") == user_id), None)


# ── de los datos de Google ────────────────────────────────────────────────────

def test_el_nombre_y_el_apellido_salen_de_given_name_y_family_name():
    assert names_from_claims({"given_name": "Ana", "family_name": "Gómez"}) == ("Ana", "Gómez")


def test_si_solo_viene_name_la_primera_palabra_es_el_nombre_y_el_resto_el_apellido():
    assert names_from_claims({"name": "Ana María Gómez Paz"}) == ("Ana", "María Gómez Paz")
    assert names_from_claims({"name": "Madonna"}) == ("Madonna", None)


def test_se_limpian_los_espacios_y_se_corta_al_largo_del_perfil():
    first, last = names_from_claims({"given_name": "  Ana   María ", "family_name": "G" * 50})

    assert first == "Ana María"
    assert last == "G" * NAME_MAX


def test_sin_nombre_ni_apellido_no_hay_nada_que_guardar():
    assert names_from_claims({}) == (None, None)
    assert names_from_claims({"given_name": "  ", "name": ""}) == (None, None)


# ── al crear la cuenta ────────────────────────────────────────────────────────

def test_la_cuenta_nueva_con_google_crea_su_perfil_con_el_nombre_y_el_apellido(client, google, db, profiles):
    r = login_google(client, id_token({"given_name": "Ana", "family_name": "Gómez"}))

    assert r.status_code == 200
    assert profile_of(db) == ("Ana", "Gómez")


def test_volver_a_entrar_con_google_no_cambia_el_perfil(client, google, db, profiles):
    login_google(client, id_token({"given_name": "Ana", "family_name": "Gómez"}))
    db.execute(text("UPDATE user_profiles SET first_name = 'Anita'"))
    db.commit()

    login_google(client, id_token({"given_name": "Otra", "family_name": "Persona"}))

    assert profile_of(db) == ("Anita", "Gómez")


def test_una_cuenta_que_ya_existia_no_recibe_el_nombre_de_google(client, google, db, profiles):
    register_user(client)

    r = login_google(client, id_token({"given_name": "Ana", "family_name": "Gómez"}))

    assert r.status_code == 200
    assert profile_of(db) is None


def test_si_el_perfil_ya_existia_no_se_pisa(db, profiles):
    db.execute(text("INSERT INTO user_profiles (user_id, first_name, last_name) VALUES ('u1', 'Propio', 'Mio')"))
    db.commit()

    assert seed_profile_names(db, "u1", {"given_name": "Ana", "family_name": "Gómez"}) is True

    assert db.execute(text("SELECT first_name, last_name FROM user_profiles WHERE user_id = 'u1'")).one() == ("Propio", "Mio")


def test_sin_nombre_en_el_token_no_se_crea_perfil(client, google, db, profiles):
    login_google(client)

    assert db.execute(text("SELECT count(*) FROM user_profiles")).scalar() == 0


def test_si_la_tabla_de_perfiles_todavia_no_existe_la_cuenta_se_crea_igual(client, google, db):
    r = login_google(client, id_token({"given_name": "Ana", "family_name": "Gómez"}))

    assert r.status_code == 200
    assert db.execute(text("SELECT count(*) FROM auth_users")).scalar() == 1


def test_si_falla_la_escritura_del_perfil_no_se_cae_el_ingreso(client, google, db, profiles, monkeypatch):
    from sqlalchemy.exc import OperationalError

    original = db.execute

    def failing(statement, *args, **kwargs):
        if "INSERT INTO user_profiles" in str(statement):
            raise OperationalError("insert", {}, Exception("boom"))
        return original(statement, *args, **kwargs)

    monkeypatch.setattr(db, "execute", failing)

    r = login_google(client, id_token({"given_name": "Ana", "family_name": "Gómez"}))

    assert r.status_code == 200 and r.json()["access_token"]
