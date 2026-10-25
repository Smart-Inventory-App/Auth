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
    DEBUG: bool = True

    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    # URL https pública del logo que se muestra arriba de los mails (vacío = mail sin logo).
    EMAIL_LOGO_URL: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
