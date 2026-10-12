from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import EmailStr
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import create_access_token, hash_password, verify_password
from app.models.admin import AdminUser
from app.models.user import User
from app.schemas.admin import (
    AdminCreate,
    AdminLoginRequest,
    AdminResponse,
    AdminTokenResponse,
    AdminWhitelistResponse,
    CheckEmailRequest,
    CheckEmailResponse,
    SetPasswordRequest,
)

router = APIRouter(prefix="/auth/admin", tags=["admin"])
_bearer = HTTPBearer()


def _get_user_by_email(email: str, db: Session) -> User | None:
    return db.query(User).filter(User.email == email).first()


def _get_admin_by_email(email: str, db: Session) -> AdminUser | None:
    return db.query(AdminUser).filter(AdminUser.email == email).first()


def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
) -> AdminUser:
    """Valida el JWT emitido por este mismo servicio y exige que el email
    pertenezca a la whitelist de administradores activos."""
    cred_exc = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="auth.invalid_token")
    try:
        payload = jwt.decode(credentials.credentials, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        email = payload.get("email")
        if not email:
            raise cred_exc
    except JWTError:
        raise cred_exc

    admin = _get_admin_by_email(email, db)
    if not admin or not admin.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="auth.not_an_admin")
    return admin


@router.post("/check", response_model=CheckEmailResponse)
def check_email(body: CheckEmailRequest, db: Session = Depends(get_db)):
    """Paso 1 del login del backoffice: dado un email, indica si existe cuenta,
    si es admin y si ya tiene contraseña definida."""
    admin = _get_admin_by_email(body.email, db)
    if admin and admin.is_active:
        return CheckEmailResponse(
            exists=True, is_admin=True, password_set=admin.password_set, full_name=admin.full_name
        )

    user = _get_user_by_email(body.email, db)
    if user and user.is_active:
        return CheckEmailResponse(exists=True, is_admin=False, password_set=True)

    return CheckEmailResponse(exists=False, is_admin=False, password_set=False)


@router.post("/set-password", status_code=status.HTTP_204_NO_CONTENT)
def set_password(body: SetPasswordRequest, db: Session = Depends(get_db)):
    """Primer inicio de sesión de un admin whitelisteado: define su contraseña,
    que se registra en `auth_users` como la de cualquier otro usuario."""
    admin = _get_admin_by_email(body.email, db)
    if not admin or not admin.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="auth.not_an_admin")
    if admin.password_set:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="auth.password_already_set")

    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="auth.password_too_short")
    if not any(c.isupper() for c in body.password):
        raise HTTPException(status_code=400, detail="auth.password_missing_uppercase")
    if not any(c.islower() for c in body.password):
        raise HTTPException(status_code=400, detail="auth.password_missing_lowercase")
    if not any(c.isdigit() for c in body.password):
        raise HTTPException(status_code=400, detail="auth.password_missing_digit")

    existing_user = _get_user_by_email(body.email, db)
    if existing_user:
        # El email ya tenía cuenta en auth_users (p. ej. era usuario de la app):
        # lo damos por válido, el admin inicia sesión con esa contraseña existente.
        admin.password_set = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="auth.email_already_registered",
        )

    user = User(email=body.email, hashed_password=hash_password(body.password))
    db.add(user)
    admin.password_set = True
    db.commit()


@router.get("/whitelist", response_model=AdminWhitelistResponse)
def whitelist_status(email: EmailStr = Query(...), db: Session = Depends(get_db)):
    """Estado crudo de la whitelist (sin colapsar inactivo → no-admin). Lo usan
    otros servicios para replicar reglas de login propias (p. ej. distinguir
    'admin deshabilitado' de 'no es admin')."""
    admin = _get_admin_by_email(email, db)
    if not admin:
        return AdminWhitelistResponse(is_admin=False, is_active=False, password_set=False)
    return AdminWhitelistResponse(
        is_admin=True, is_active=admin.is_active, password_set=admin.password_set, full_name=admin.full_name
    )


@router.post("/login", response_model=AdminTokenResponse)
def login(body: AdminLoginRequest, db: Session = Depends(get_db)):
    """Login de admin: exige whitelist + contraseña definida, y valida las
    credenciales contra `auth_users` igual que el login genérico."""
    admin = _get_admin_by_email(body.email, db)
    if not admin or not admin.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="auth.not_an_admin")
    if not admin.password_set:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="auth.password_not_set")

    user = _get_user_by_email(body.email, db)
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="auth.invalid_credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="auth.account_disabled")

    return AdminTokenResponse(access_token=create_access_token(str(user.id), user.email))


@router.get("/admins", response_model=list[AdminResponse])
def list_admins(db: Session = Depends(get_db), _: AdminUser = Depends(get_current_admin)):
    return db.query(AdminUser).order_by(AdminUser.created_at.desc()).all()


@router.post("/admins", response_model=AdminResponse, status_code=status.HTTP_201_CREATED)
def create_admin(
    data: AdminCreate,
    db: Session = Depends(get_db),
    _: AdminUser = Depends(get_current_admin),
):
    if _get_admin_by_email(data.email, db):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="auth.admin_already_exists")

    admin = AdminUser(email=data.email, full_name=data.full_name, password_set=False)
    db.add(admin)
    db.commit()
    db.refresh(admin)
    return admin
