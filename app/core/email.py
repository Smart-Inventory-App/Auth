import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import settings


def _send_code_email(to_email: str, code: str, subject: str, intro: str) -> None:
    if not settings.SMTP_HOST or not settings.SMTP_USER:
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USER
    msg["To"] = to_email

    logo_html = (
        f'<img src="{settings.EMAIL_LOGO_URL}" alt="Smart Inventory" width="220" style="display:block;margin:0 0 20px;">'
        if settings.EMAIL_LOGO_URL
        else ""
    )
    text = f"{intro}\nTu código es: {code}\nExpira en {settings.JWT_RESET_EXPIRE_MINUTES} minutos."
    html = f"""
<html>
<body style="font-family: sans-serif; padding: 24px; color: #1a1a1a;">
  {logo_html}
  <p>{intro}</p>
  <p>Tu código de verificación es:</p>
  <div style="font-size: 36px; font-weight: bold; letter-spacing: 8px; margin: 24px 0; color: #1B3A8F;">
    {code}
  </div>
  <p>Este código expira en <strong>{settings.JWT_RESET_EXPIRE_MINUTES} minutos</strong>.</p>
  <p style="color: #666; font-size: 13px;">Si no solicitaste este código, podés ignorar este mensaje.</p>
</body>
</html>
"""

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
        server.starttls()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.send_message(msg)


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
