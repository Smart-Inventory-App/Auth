import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import settings


def send_reset_code_email(to_email: str, code: str) -> None:
    if not settings.SMTP_HOST or not settings.SMTP_USER:
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Código de recuperación - Smart Inventory"
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USER
    msg["To"] = to_email

    text = f"Tu código de recuperación es: {code}\nExpira en {settings.JWT_RESET_EXPIRE_MINUTES} minutos."
    html = f"""
<html>
<body style="font-family: sans-serif; padding: 24px; color: #1a1a1a;">
  <p>Recibimos una solicitud para restablecer tu contraseña en <strong>Smart Inventory</strong>.</p>
  <p>Tu código de verificación es:</p>
  <div style="font-size: 36px; font-weight: bold; letter-spacing: 8px; margin: 24px 0; color: #2563eb;">
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
