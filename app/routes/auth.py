import logging
import secrets
import string
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.email import send_reset_code_email, send_set_password_code_email, send_welcome_email
from app.core.google import GoogleTokenError, GoogleUnreachable, verify_google_id_token
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

MAX_CODE_ATTEMPTS = 5

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])
_bearer = HTTPBearer()


def _send_welcome(email: str, via_google: bool) -> None:
    """Mail de bienvenida. Se manda después de responder y nunca hace fallar el alta de la cuenta."""
    try:
        send_welcome_email(email, via_google=via_google)
    except Exception:
        logger.exception("No se pudo enviar el mail de bienvenida a %s", email)


def _get_user_by_email(email: str, db: Session):
    return db.query(User).filter(User.email == email).first()


def _get_user_by_token(credentials: HTTPAuthorizationCredentials, db: Session) -> User:
    try:
        payload = jwt.decode(credentials.credentials, settings.JWT_SECRET,
                             algorithms=[settings.JWT_ALGORITHM])
        user_id = uuid.UUID(str(payload.get("sub")))
    except (JWTError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="auth.invalid_token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="auth.user_not_found")
    return user

def _check_token(user: User, db: Session, token: str | None):
    if token and user.firebase_token != token:
        user.firebase_token = token
        db.add(user)
        db.commit()
    

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="auth.password_too_short")
    if not any(c.isupper() for c in body.password):
        raise HTTPException(status_code=400, detail="auth.password_missing_uppercase")
    if not any(c.islower() for c in body.password):
        raise HTTPException(status_code=400, detail="auth.password_missing_lowercase")
    if not any(c.isdigit() for c in body.password):
        raise HTTPException(status_code=400, detail="auth.password_missing_digit")
    if _get_user_by_email(body.email, db):
        raise HTTPException(status_code=400, detail="auth.email_already_registered")
    user = User(email=body.email, hashed_password=hash_password(body.password))
    db.add(user)
    db.commit()
    background_tasks.add_task(_send_welcome, body.email, False)


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = _get_user_by_email(body.email, db)
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="auth.invalid_credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="auth.account_disabled")
    _check_token(user, db, body.firebase_token)
    return LoginResponse(access_token=create_access_token(str(user.id), user.email))


@router.post("/check-email")
def check_email(body: CheckEmailRequest, db: Session = Depends(get_db)):
    user = _get_user_by_email(body.email, db)
    if not user:
        return {"exists": False}
    return {"exists": True, "password_set": bool(user.has_password)}


@router.post("/forgot-password")
def forgot_password(body: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = _get_user_by_email(body.email, db)
    if not user:
        return {"detail": "auth.reset_code_sent"}

    code = "".join(secrets.choice(string.digits) for _ in range(6))
    expires_at = datetime.utcnow() + timedelta(minutes=settings.JWT_RESET_EXPIRE_MINUTES)

    reset = PasswordResetCode(user_id=user.id, code=code, expires_at=expires_at)
    db.add(reset)
    db.commit()

    try:
        if user.has_password:
            send_reset_code_email(user.email, code)
        else:
            send_set_password_code_email(user.email, code)
    except Exception:
        # No se le avisa a quien pregunta (no revelar si el mail existe), pero queda en el log
        logger.exception("No se pudo enviar el mail con el código a %s", user.email)

    response: dict = {"detail": "auth.reset_code_sent"}
    if settings.DEBUG:
        response["debug_code"] = code
    return response


@router.post("/verify-code")
def verify_code(body: VerifyCodeRequest, db: Session = Depends(get_db)):
    user = _get_user_by_email(body.email, db)
    if not user:
        raise HTTPException(status_code=400, detail="auth.invalid_code")

    # Solo cuenta el código vigente más reciente: es el único que se puede estar intentando adivinar
    latest = (
        db.query(PasswordResetCode)
        .filter(
            PasswordResetCode.user_id == user.id,
            PasswordResetCode.used == False,
            PasswordResetCode.expires_at > datetime.utcnow(),
        )
        .order_by(PasswordResetCode.created_at.desc())
        .first()
    )
    if not latest:
        raise HTTPException(status_code=400, detail="auth.invalid_or_expired_code")

    if not secrets.compare_digest(latest.code, body.code):
        latest.failed_attempts = (latest.failed_attempts or 0) + 1
        too_many = latest.failed_attempts >= MAX_CODE_ATTEMPTS
        if too_many:
            latest.used = True
        db.commit()
        if too_many:
            raise HTTPException(status_code=429, detail="auth.too_many_attempts")
        raise HTTPException(status_code=400, detail="auth.invalid_or_expired_code")

    reset = latest

    reset.used = True
    db.commit()
    return {"reset_token": create_reset_token(str(user.id))}


@router.post("/reset-password")
def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_db)):
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="auth.password_too_short")
    try:
        user_id = uuid.UUID(str(decode_reset_token(body.reset_token)))
    except ValueError:
        raise HTTPException(status_code=400, detail="auth.invalid_or_expired_token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=400, detail="auth.invalid_or_expired_token")

    if verify_password(body.new_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="auth.password_same_as_current")

    user.hashed_password = hash_password(body.new_password)
    user.has_password = True
    db.commit()


@router.post("/check-new-password")
def check_new_password(body: ResetPasswordRequest, db: Session = Depends(get_db)):
    try:
        user_id = uuid.UUID(str(decode_reset_token(body.reset_token)))
    except ValueError:
        raise HTTPException(status_code=400, detail="auth.invalid_or_expired_token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=400, detail="auth.invalid_or_expired_token")

    return {"different": not verify_password(body.new_password, user.hashed_password)}


@router.post("/google", response_model=LoginResponse)
def google_login(body: GoogleAuthRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    client_ids = settings.google_client_ids
    if not client_ids:
        raise HTTPException(status_code=503, detail="auth.google_not_configured")

    try:
        claims = verify_google_id_token(body.id_token, client_ids)
    except GoogleUnreachable:
        raise HTTPException(status_code=503, detail="auth.google_unreachable")
    except GoogleTokenError:
        raise HTTPException(status_code=401, detail="auth.google_invalid_token")

    email = claims.get("email")
    if not email or claims.get("email_verified") not in (True, "true"):
        raise HTTPException(status_code=401, detail="auth.google_email_not_verified")

    user = _get_user_by_email(email, db)
    if not user:
        user = User(
            email=email,
            hashed_password=hash_password(secrets.token_hex(32)),
            has_password=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        # Solo al crearse la cuenta: entrar de nuevo con Google no vuelve a mandar la bienvenida
        background_tasks.add_task(_send_welcome, email, True)

    # Si el email ya tenía cuenta se entra en ella: su contraseña no se toca, puede usar Google o su contraseña.
    if not user.is_active:
        raise HTTPException(status_code=403, detail="auth.account_disabled")

    return LoginResponse(access_token=create_access_token(str(user.id), user.email))


class FirebaseTokenRequest(BaseModel):
    firebase_token: str


@router.patch("/firebase-token", status_code=status.HTTP_204_NO_CONTENT)
def update_firebase_token(
    body: FirebaseTokenRequest,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
):
    user = _get_user_by_token(credentials, db)
    _check_token(user, db, body.firebase_token)


@router.get("/me", response_model=MeResponse)
def me(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
):
    user = _get_user_by_token(credentials, db)
    return MeResponse(id=str(user.id), email=user.email)
