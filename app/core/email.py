import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape

from app.core.config import settings

logger = logging.getLogger(__name__)

BRAND_BLUE = "#1B3A8F"


def _logo_html() -> str:
    """Logo de la app arriba del mail. Sin EMAIL_LOGO_URL no se muestra nada (el mail sigue siendo válido)."""
    if not settings.EMAIL_LOGO_URL:
        return ""
    return (
        f'<img src="{escape(settings.EMAIL_LOGO_URL, quote=True)}" alt="Smart Inventory" width="220" '
        'style="display:block;margin:0 0 20px;">'
    )


def _page(content_html: str) -> str:
    return f"""
<html>
<body style="font-family: sans-serif; padding: 24px; color: #1a1a1a;">
  {_logo_html()}
  {content_html}
</body>
</html>
"""


def _deliver(to_email: str, subject: str, text: str, html: str) -> None:
    if not settings.SMTP_HOST or not settings.SMTP_USER:
        # Sin SMTP no sale ningún mail: se avisa en el log para que no parezca que se envió
        logger.warning("SMTP no configurado (SMTP_HOST / SMTP_USER): no se envió el mail a %s", to_email)
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USER
    msg["To"] = to_email
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
        server.starttls()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.send_message(msg)


def _send_code_email(to_email: str, code: str, subject: str, intro: str) -> None:
    text = f"{intro}\nTu código es: {code}\nExpira en {settings.JWT_RESET_EXPIRE_MINUTES} minutos."
    html = _page(f"""
  <p>{intro}</p>
  <p>Tu código de verificación es:</p>
  <div style="font-size: 36px; font-weight: bold; letter-spacing: 8px; margin: 24px 0; color: {BRAND_BLUE};">
    {code}
  </div>
  <p>Este código expira en <strong>{settings.JWT_RESET_EXPIRE_MINUTES} minutos</strong>.</p>
  <p style="color: #666; font-size: 13px;">Si no solicitaste este código, podés ignorar este mensaje.</p>
""")
    _deliver(to_email, subject, text, html)


def send_reset_code_email(to_email: str, code: str) -> None:
    _send_code_email(
        to_email,
        code,
        subject="Código de recuperación - Smart Inventory",
        intro="Recibimos una solicitud para restablecer tu contraseña en <strong>Smart Inventory</strong>.",
    )


def send_set_password_code_email(to_email: str, code: str) -> None:
    """Para cuentas creadas por Google que todavía no tienen contraseña propia."""
    _send_code_email(
        to_email,
        code,
        subject="Configurá tu contraseña - Smart Inventory",
        intro=(
            "Tu cuenta de <strong>Smart Inventory</strong> entró hasta ahora con Google. "
            "Con este código podés definir una contraseña para también poder iniciar sesión sin Google."
        ),
    )


WELCOME_STEPS = [
    ("Cargá tus productos", "Desde la pestaña «Cargar» podés agregarlos a mano o escanear el código de barras, y registrar "
                            "las entradas y salidas de stock."),
    ("Revisá tu inventario", "En «Inventario» ves el stock de cada producto, su vencimiento y cuánto tiempo te va a durar."),
    ("Mirá tus alertas", "En «Alertas» te avisamos de los productos próximos a vencer, los que se están por agotar y los "
                         "que corren riesgo de vencerse por consumirse lento."),
    ("Activá las notificaciones", "Desde «Perfil» activá las notificaciones para recibir los avisos en tu celular y por mail, "
                                  "y ajustá con cuántos días de anticipación querés que te avisemos."),
]


def send_welcome_email(to_email: str, via_google: bool = False) -> None:
    """Bienvenida al crear la cuenta (con mail y contraseña o con Google)."""
    subject = "¡Te damos la bienvenida a Smart Inventory!"
    how = (
        "Creaste tu cuenta con tu cuenta de Google, así que no necesitás una contraseña para entrar. Si más adelante "
        "querés también poder ingresar con mail y contraseña, podés definir una iniciando sesión "
        "normalmente y validando esta dirección de mail."
        if via_google
        else "Tu cuenta ya está lista: ingresá con tu mail y la contraseña que elegiste."
    )
    intro = (
        "Gracias por sumarte a Smart Inventory. Te ayudamos a tener el control de lo que tenés en casa o en tu negocio: "
        "qué hay, cuánto te va a durar y qué está por vencerse, para que no se pierda nada."
    )
    steps_text = "\n".join(f"{i}. {title}: {detail}" for i, (title, detail) in enumerate(WELCOME_STEPS, 1))
    text = (
        f"¡Te damos la bienvenida a Smart Inventory!\n\n{intro}\n\n{how}\n\nPara empezar:\n{steps_text}\n\n"
        "Si no creaste esta cuenta, podés ignorar este mensaje."
    )
    steps_html = "".join(
        f'<li style="margin-bottom:10px;"><strong>{escape(title)}.</strong> {escape(detail)}</li>'
        for title, detail in WELCOME_STEPS
    )
    html = _page(f"""
  <h2 style="color: {BRAND_BLUE}; margin: 0 0 12px;">¡Te damos la bienvenida a Smart Inventory!</h2>
  <p>{escape(intro)}</p>
  <p>{escape(how)}</p>
  <p style="margin-top: 24px;"><strong>Para empezar:</strong></p>
  <ol style="padding-left: 20px; line-height: 1.5;">{steps_html}</ol>
  <p style="color: #666; font-size: 13px; margin-top: 24px;">Si no creaste esta cuenta, podés ignorar este mensaje.</p>
""")
    _deliver(to_email, subject, text, html)
