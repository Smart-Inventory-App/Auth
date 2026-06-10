import random
import secrets
import string
from datetime import datetime, timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.email import send_reset_code_email
from app.core.security import (
    create_access_token,
    create_reset_token,
    decode_reset_token,
    hash_password,
    verify_password,
)
from app.models.user import PasswordResetCode, User
from app.schemas.auth import (
    CheckEmailRequest,
    ForgotPasswordRequest,
    GoogleAuthRequest,
    LoginRequest,
    LoginResponse,
    MeResponse,
    RegisterRequest,
    ResetPasswordRequest,
    VerifyCodeRequest,
)

router = APIRouter(prefix="/auth", tags=["auth"])
_bearer = HTTPBearer()


def _get_user_by_email(email: str, db: Session):
    return db.query(User).filter(User.email == email).first()


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="La contraseña debe tener al menos 8 caracteres")
    if _get_user_by_email(body.email, db):
        raise HTTPException(status_code=400, detail="El email ya está registrado")
    user = User(email=body.email, hashed_password=hash_password(body.password))
    db.add(user)
    db.commit()


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = _get_user_by_email(body.email, db)
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Email o contraseña incorrectos")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Cuenta desactivada")
    return LoginResponse(access_token=create_access_token(str(user.id), user.email))


@router.post("/check-email")
def check_email(body: CheckEmailRequest, db: Session = Depends(get_db)):
    return {"exists": _get_user_by_email(body.email, db) is not None}


@router.post("/forgot-password")
def forgot_password(body: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = _get_user_by_email(body.email, db)
    if not user:
        # No revelar si el email existe
        return {"detail": "Si el email existe, recibirás un código"}

    code = "".join(random.choices(string.digits, k=6))
    expires_at = datetime.utcnow() + timedelta(minutes=settings.JWT_RESET_EXPIRE_MINUTES)

    reset = PasswordResetCode(user_id=user.id, code=code, expires_at=expires_at)
    db.add(reset)
    db.commit()

    try:
        send_reset_code_email(user.email, code)
    except Exception:
        pass

    response: dict = {"detail": "Si el email existe, recibirás un código"}
    if settings.DEBUG:
        response["debug_code"] = code
    return response


@router.post("/verify-code")
def verify_code(body: VerifyCodeRequest, db: Session = Depends(get_db)):
    user = _get_user_by_email(body.email, db)
    if not user:
        raise HTTPException(status_code=400, detail="Código inválido")

    reset = (
        db.query(PasswordResetCode)
        .filter(
            PasswordResetCode.user_id == user.id,
            PasswordResetCode.code == body.code,
            PasswordResetCode.used == False,
            PasswordResetCode.expires_at > datetime.utcnow(),
        )
        .order_by(PasswordResetCode.created_at.desc())
        .first()
    )
    if not reset:
        raise HTTPException(status_code=400, detail="Código inválido o expirado")

    reset.used = True
    db.commit()
    return {"reset_token": create_reset_token(str(user.id))}


@router.post("/reset-password")
def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_db)):
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="La contraseña debe tener al menos 8 caracteres")
    try:
        user_id = decode_reset_token(body.reset_token)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=400, detail="Token inválido")

    user.hashed_password = hash_password(body.new_password)
    db.commit()


@router.post("/google", response_model=LoginResponse)
def google_login(body: GoogleAuthRequest, db: Session = Depends(get_db)):
    try:
        r = httpx.get(
            "https://www.googleapis.com/oauth2/v1/userinfo",
            params={"access_token": body.access_token},
            timeout=10,
        )
    except httpx.RequestError:
        raise HTTPException(status_code=503, detail="No se pudo contactar a Google")

    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Token de Google inválido")

    info = r.json()
    email = info.get("email")
    if not email or not info.get("verified_email"):
        raise HTTPException(status_code=401, detail="Email de Google no verificado")

    user = _get_user_by_email(email, db)
    if not user:
        user = User(email=email, hashed_password=hash_password(secrets.token_hex(32)))
        db.add(user)
        db.commit()
        db.refresh(user)

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Cuenta desactivada")

    return LoginResponse(access_token=create_access_token(str(user.id), user.email))


@router.get("/me", response_model=MeResponse)
def me(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
):
    try:
        payload = jwt.decode(credentials.credentials, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return MeResponse(id=str(user.id), email=user.email)
