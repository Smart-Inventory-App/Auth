from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


class AdminResponse(BaseModel):
    id: int
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool
    password_set: bool
    created_at: Optional[datetime] = None
    # Solo al dar de alta un admin que todavía no tiene cuenta: con este código
    # define su primera contraseña. Nunca se guarda ni se vuelve a mostrar.
    invite_token: Optional[str] = None

    class Config:
        from_attributes = True


class AdminCreate(BaseModel):
    """Alta de admin: solo email y nombre. La contraseña la define el propio
    admin en su primer inicio de sesión."""
    email: EmailStr
    full_name: Optional[str] = None


class CheckEmailRequest(BaseModel):
    email: EmailStr


class CheckEmailResponse(BaseModel):
    exists: bool
    is_admin: bool
    password_set: bool
    full_name: Optional[str] = None


class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str


class SetPasswordRequest(BaseModel):
    email: EmailStr
    password: str
    invite_token: str


class AdminTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AdminWhitelistResponse(BaseModel):
    """Estado crudo de la whitelist para un email, sin colapsar 'inactivo' en
    'no es admin' — a diferencia de /check, que sí lo hace. Pensado para que
    otros servicios (p. ej. backoffice) repliquen su propia lógica de login."""
    is_admin: bool
    is_active: bool
    password_set: bool
    full_name: Optional[str] = None
