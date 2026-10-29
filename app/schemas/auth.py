from typing import Optional

from pydantic import BaseModel, EmailStr


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    firebase_token: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    # La cuenta tiene una contraseña inicial que le dio un administrador: tiene que cambiarla antes de seguir
    must_change_password: bool = False


class CheckEmailRequest(BaseModel):
    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class VerifyCodeRequest(BaseModel):
    email: EmailStr
    code: str


class ResetPasswordRequest(BaseModel):
    reset_token: str
    new_password: str


class MeResponse(BaseModel):
    id: str
    email: str
    must_change_password: bool = False


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class GoogleAuthRequest(BaseModel):
    # El idToken que Google le dio a la app. Se verifica contra GOOGLE_CLIENT_ID
    id_token: str
