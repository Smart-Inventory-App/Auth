from datetime import datetime, timedelta

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def password_rule_error(password: str) -> str | None:
    """Por qué una contraseña no sirve (las mismas reglas del registro), o `None` si cumple."""
    if len(password) < 8:
        return "auth.password_too_short"
    if not any(c.isupper() for c in password):
        return "auth.password_missing_uppercase"
    if not any(c.islower() for c in password):
        return "auth.password_missing_lowercase"
    if not any(c.isdigit() for c in password):
        return "auth.password_missing_digit"
    return None


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(user_id: str, email: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": user_id, "email": email, "exp": expire},
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_reset_token(user_id: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_RESET_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": user_id, "type": "reset", "exp": expire},
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_reset_token(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "reset":
            raise ValueError("auth.invalid_or_expired_token")
        return payload["sub"]
    except JWTError:
        raise ValueError("auth.invalid_or_expired_token")


def create_admin_invite_token(email: str) -> str:
    """Código de invitación de un admin pendiente.

    Usa `invite_for` y no `sub`/`email`: así no sirve como token de acceso en
    ningún servicio (todos exigen `sub` o `email`), solo para definir la primera
    contraseña. Deja de servir apenas el admin la define (`password_set`).
    """
    expire = datetime.utcnow() + timedelta(hours=settings.ADMIN_INVITE_EXPIRE_HOURS)
    return jwt.encode(
        {"invite_for": email, "type": "admin_invite", "exp": expire},
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_admin_invite_token(token: str) -> str:
    """Devuelve el email al que se invitó, o levanta ValueError si no sirve."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        raise ValueError("auth.invalid_invite")
    email = payload.get("invite_for")
    if payload.get("type") != "admin_invite" or not email:
        raise ValueError("auth.invalid_invite")
    return email
