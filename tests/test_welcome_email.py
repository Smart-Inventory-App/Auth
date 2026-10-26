"""Mail de bienvenida al crear la cuenta (con mail y contraseña o con Google) y logo en los mails."""
import pytest

from app.core import email as email_mod
from app.core.config import settings
from app.models.user import User
from tests.conftest import TEST_EMAIL, VALID_PASSWORD, register_user
from tests.test_email_and_health import FakeSMTP, smtp  # noqa: F401 — fixture y servidor falso
from tests.test_google_login import google, login_google  # noqa: F401


@pytest.fixture
def bienvenidas(monkeypatch):
    """Registra las bienvenidas que se hubieran mandado."""
    enviadas = []
    monkeypatch.setattr(
        "app.routes.auth.send_welcome_email",
        lambda to, via_google=False: enviadas.append({"to": to, "via_google": via_google}),
    )
    return enviadas


def cuerpos(msg):
    partes = {p.get_content_type(): p.get_payload(decode=True).decode() for p in msg.get_payload()}
    return partes["text/plain"], partes["text/html"]


# ── cuándo se manda ──────────────────────────────────────────────────────────

def test_al_registrarse_con_mail_y_contrasena_se_manda_la_bienvenida(client, bienvenidas):
    assert register_user(client).status_code == 201
    assert bienvenidas == [{"to": TEST_EMAIL, "via_google": False}]


def test_un_registro_rechazado_no_manda_bienvenida(client, bienvenidas):
    register_user(client)
    bienvenidas.clear()
    assert register_user(client).status_code == 400  # mail repetido
    assert client.post("/auth/register", json={"email": "otro@example.com", "password": "corta"}).status_code == 400
    assert bienvenidas == []


def test_al_crear_la_cuenta_con_google_se_manda_la_bienvenida(client, google, bienvenidas):
    assert login_google(client).status_code == 200
    assert bienvenidas == [{"to": TEST_EMAIL, "via_google": True}]


def test_volver_a_entrar_con_google_no_repite_la_bienvenida(client, google, bienvenidas):
    login_google(client)
    login_google(client)
    assert len(bienvenidas) == 1


def test_entrar_con_google_a_una_cuenta_ya_registrada_no_manda_bienvenida(client, google, bienvenidas):
    register_user(client)
    bienvenidas.clear()
    login_google(client)
    assert bienvenidas == []


def test_si_falla_el_envio_la_cuenta_se_crea_igual_y_queda_en_el_log(client, monkeypatch, caplog, db):
    def explota(*a, **kw):
        raise RuntimeError("smtp caído")

    monkeypatch.setattr("app.routes.auth.send_welcome_email", explota)
    with caplog.at_level("ERROR", logger="app.routes.auth"):
        r = register_user(client)
    assert r.status_code == 201
    assert db.query(User).filter(User.email == TEST_EMAIL).first() is not None
    assert "No se pudo enviar el mail de bienvenida" in caplog.text


def test_si_falla_el_envio_el_login_con_google_responde_bien(client, google, monkeypatch):
    monkeypatch.setattr("app.routes.auth.send_welcome_email", lambda *a, **kw: 1 / 0)
    assert login_google(client).status_code == 200


# ── contenido del mail ───────────────────────────────────────────────────────

def test_la_bienvenida_llega_al_mail_correcto_con_asunto_y_remitente(smtp, monkeypatch):
    monkeypatch.setattr(settings, "SMTP_FROM", "noreply@smartinventory.com")
    email_mod.send_welcome_email("nuevo@example.com")
    msg = smtp.instancias[0].enviados[0]
    assert msg["To"] == "nuevo@example.com"
    assert msg["From"] == "noreply@smartinventory.com"
    assert "bienvenida" in msg["Subject"]
    assert "Smart Inventory" in msg["Subject"]


def test_la_bienvenida_explica_los_primeros_pasos_en_texto_y_html(smtp):
    email_mod.send_welcome_email("nuevo@example.com")
    texto, html = cuerpos(smtp.instancias[0].enviados[0])
    for paso in ("Cargá tus productos", "Revisá tu inventario", "Mirá tus alertas", "Activá las notificaciones"):
        assert paso in texto
        assert paso in html
    assert "contraseña que elegiste" in texto


def test_la_bienvenida_de_google_explica_que_no_necesita_contrasena(smtp):
    email_mod.send_welcome_email("nuevo@example.com", via_google=True)
    texto, html = cuerpos(smtp.instancias[0].enviados[0])
    assert "cuenta de Google" in texto
    assert "iniciando sesión normalmente y validando esta dirección de mail" in html
    assert "Olvidé mi contraseña" not in html
    assert "contraseña que elegiste" not in texto


def test_los_mails_llevan_el_logo_si_hay_url_configurada(smtp, monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_LOGO_URL", "https://cdn.example.com/logo.png")
    email_mod.send_welcome_email("nuevo@example.com")
    email_mod.send_reset_code_email("nuevo@example.com", "123456")
    email_mod.send_set_password_code_email("nuevo@example.com", "123456")
    for msg in smtp.instancias[0].enviados:
        assert 'src="https://cdn.example.com/logo.png"' in cuerpos(msg)[1]


def test_los_mails_no_llevan_imagen_sin_url_de_logo(smtp, monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_LOGO_URL", "")
    email_mod.send_welcome_email("nuevo@example.com")
    assert "<img" not in cuerpos(smtp.instancias[0].enviados[0])[1]


def test_la_url_del_logo_no_puede_romper_el_html(smtp, monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_LOGO_URL", 'https://x.com/a.png" onerror="alert(1)')
    email_mod.send_welcome_email("nuevo@example.com")
    html = cuerpos(smtp.instancias[0].enviados[0])[1]
    assert 'onerror="alert' not in html


def test_sin_smtp_la_bienvenida_no_rompe_y_deja_aviso_en_el_log(monkeypatch, caplog):
    monkeypatch.setattr(settings, "SMTP_HOST", "")
    with caplog.at_level("WARNING", logger="app.core.email"):
        email_mod.send_welcome_email("nuevo@example.com")
    assert "SMTP no configurado" in caplog.text
    assert "nuevo@example.com" in caplog.text
