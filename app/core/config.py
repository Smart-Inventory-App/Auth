from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://user:password@localhost:5432/tpp_db"
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_EXPIRE_MINUTES: int = 30
    JWT_RESET_EXPIRE_MINUTES: int = 15
    # Vigencia del código de invitación con el que un admin pendiente define su contraseña.
    ADMIN_INVITE_EXPIRE_HOURS: int = 168
    # Token compartido entre servicios. Vacío = los endpoints internos quedan cerrados.
    INTERNAL_SERVICE_TOKEN: str = ""
    DEBUG: bool = False

    # ID de cliente (tipo «Aplicación web») de Google Cloud con el que la app pide el idToken. Se pueden poner varios
    # separados por comas. Vacío = el login con Google queda deshabilitado.
    GOOGLE_CLIENT_ID: str = ""

    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    # URL https pública del logo que se muestra arriba de los mails (vacío = mail sin logo).
    EMAIL_LOGO_URL: str = ""

    @property
    def google_client_ids(self) -> list[str]:
        return [item.strip() for item in self.GOOGLE_CLIENT_ID.split(",") if item.strip()]

    class Config:
        env_file = ".env"


settings = Settings()
