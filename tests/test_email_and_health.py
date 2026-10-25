"""Tests del envío de mail de recuperación, la sesión de base y el health check."""
import pytest

from app.core import email as email_mod
from app.core.config import settings
from app.core.database import get_db


class FakeSMTP:
    """Registra lo que se le pide en lugar de conectarse a un servidor."""

    instancias: list["FakeSMTP"] = []

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.tls = False
        self.login_args = None
        self.enviados = []
        FakeSMTP.instancias.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        self.tls = True

    def login(self, user, password):
        self.login_args = (user, password)

    def send_message(self, msg):
        self.enviados.append(msg)


@pytest.fixture
def smtp(monkeypatch):
    FakeSMTP.instancias = []
    monkeypatch.setattr(email_mod.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(settings, "SMTP_USER", "user@test")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "clave")
    monkeypatch.setattr(settings, "SMTP_PORT", 587)
    return FakeSMTP


# --- send_reset_code_email ---

def test_no_envia_sin_host_configurado(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", "")
    email_mod.send_reset_code_email("a@b.com", "123456")  # no debe romper


def test_no_envia_sin_usuario_configurado(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(settings, "SMTP_USER", "")
    email_mod.send_reset_code_email("a@b.com", "123456")


def test_envia_con_tls_y_credenciales(smtp):
    email_mod.send_reset_code_email("destino@test.com", "654321")

    servidor = smtp.instancias[0]
    assert servidor.host == "smtp.test"
    assert servidor.tls is True
    assert servidor.login_args == ("user@test", "clave")
    assert len(servidor.enviados) == 1


def test_el_mail_lleva_el_codigo_en_texto_y_html(smtp):
    email_mod.send_reset_code_email("destino@test.com", "654321")

    msg = smtp.instancias[0].enviados[0]
    assert msg["To"] == "destino@test.com"
    assert "Smart Inventory" in msg["Subject"]

    cuerpos = [p.get_payload(decode=True).decode() for p in msg.get_payload()]
    assert len(cuerpos) == 2
    assert all("654321" in c for c in cuerpos)


def test_el_mail_lleva_el_logo_si_hay_url_configurada(smtp, monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_LOGO_URL", "https://cdn.test/logo.png")
    email_mod.send_reset_code_email("destino@test.com", "654321")

    html = smtp.instancias[0].enviados[0].get_payload()[1].get_payload(decode=True).decode()
    assert 'src="https://cdn.test/logo.png"' in html


def test_el_mail_no_lleva_logo_si_no_hay_url(smtp, monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_LOGO_URL", "")
    email_mod.send_reset_code_email("destino@test.com", "654321")

    html = smtp.instancias[0].enviados[0].get_payload()[1].get_payload(decode=True).decode()
    assert "<img" not in html


def test_usa_smtp_from_si_esta_definido(smtp, monkeypatch):
    monkeypatch.setattr(settings, "SMTP_FROM", "no-reply@test.com")
    email_mod.send_reset_code_email("destino@test.com", "111111")
    assert smtp.instancias[0].enviados[0]["From"] == "no-reply@test.com"


def test_cae_al_usuario_si_no_hay_smtp_from(smtp, monkeypatch):
    monkeypatch.setattr(settings, "SMTP_FROM", "")
    email_mod.send_reset_code_email("destino@test.com", "111111")
    assert smtp.instancias[0].enviados[0]["From"] == "user@test"


# --- send_set_password_code_email ---

def test_set_password_email_usa_asunto_y_texto_distintos(smtp):
    email_mod.send_set_password_code_email("destino@test.com", "222222")

    msg = smtp.instancias[0].enviados[0]
    assert "Configurá tu contraseña" in msg["Subject"]
    assert "Código de recuperación" not in msg["Subject"]

    cuerpos = [p.get_payload(decode=True).decode() for p in msg.get_payload()]
    assert all("222222" in c for c in cuerpos)
    assert any("Google" in c for c in cuerpos)


def test_forgot_password_tolera_fallo_de_envio(client, monkeypatch):
    from tests.conftest import TEST_EMAIL, register_user

    register_user(client)

    def explota(*a, **kw):
        raise RuntimeError("smtp caído")

    monkeypatch.setattr("app.routes.auth.send_reset_code_email", explota)
    r = client.post("/auth/forgot-password", json={"email": TEST_EMAIL})
    assert r.status_code == 200
    assert r.json()["detail"] == "auth.reset_code_sent"


# --- get_db ---

def test_get_db_entrega_y_cierra_la_sesion():
    gen = get_db()
    session = next(gen)
    assert session is not None
    with pytest.raises(StopIteration):
        next(gen)


# --- health ---

def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}
