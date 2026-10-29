import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import EmailStr
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    create_admin_invite_token,
    decode_admin_invite_token,
    hash_password,
    password_rule_error,
    verify_password,
)
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


def verify_internal_token(x_internal_token: str | None = Header(default=None)) -> None:
    """Para endpoints que solo deben usar otros servicios. Sin
    INTERNAL_SERVICE_TOKEN configurado quedan cerrados para todos."""
    expected = settings.INTERNAL_SERVICE_TOKEN
    if not expected or not x_internal_token or not hmac.compare_digest(x_internal_token, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="auth.forbidden")


@router.post("/check", response_model=CheckEmailResponse)
def check_email(body: CheckEmailRequest, db: Session = Depends(get_db)):
    """Paso 1 del login del backoffice: dado un email, indica si existe cuenta,
    si es admin y si ya tiene contraseña definida. Es público (se consulta antes
    de loguear), así que no devuelve nada más que eso: ni el nombre."""
    admin = _get_admin_by_email(body.email, db)
    if admin and admin.is_active:
        return CheckEmailResponse(exists=True, is_admin=True, password_set=admin.password_set)

    user = _get_user_by_email(body.email, db)
    if user and user.is_active:
        return CheckEmailResponse(exists=True, is_admin=False, password_set=True)

    return CheckEmailResponse(exists=False, is_admin=False, password_set=False)


@router.post("/set-password", status_code=status.HTTP_204_NO_CONTENT)
def set_password(body: SetPasswordRequest, db: Session = Depends(get_db)):
    """Primer inicio de sesión de un admin whitelisteado: define su contraseña,
    que se registra en `auth_users` como la de cualquier otro usuario.

    Exige el código de invitación que recibió al darlo de alta. Sin él, cualquiera
    que supiera el email de un admin pendiente podría quedarse con la cuenta antes
    que su dueño. El código se valida primero y un código que no corresponde a
    ese email responde igual que uno inválido, para no revelar quién es admin."""
    try:
        invited_email = decode_admin_invite_token(body.invite_token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="auth.invalid_invite")
    if invited_email != body.email:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="auth.invalid_invite")

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
        # La cuenta se creó después de que el email entró a la whitelist. El código
        # prueba que quien lo tiene es el invitado, así que su contraseña reemplaza a
        # la que hubiera: el registro público no verifica el correo, y si alguien se
        # adelantó y registró ese email, no debe heredar el rol de admin.
        existing_user.hashed_password = hash_password(body.password)
    else:
        db.add(User(email=body.email, hashed_password=hash_password(body.password)))
    admin.password_set = True
    db.commit()


@router.get(
    "/whitelist",
    response_model=AdminWhitelistResponse,
    dependencies=[Depends(verify_internal_token)],
)
def whitelist_status(email: EmailStr = Query(...), db: Session = Depends(get_db)):
    """Estado crudo de la whitelist (sin colapsar inactivo → no-admin). Solo para
    otros servicios (header `X-Internal-Token`): dice quién es admin, si está
    activo y su nombre, así que no puede estar abierto."""
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

    # Si ya existe cuenta en auth_users (p. ej. un usuario de la app al que se
    # promueve a admin), ya tiene contraseña — no le pedimos que la redefina.
    already_has_password = _get_user_by_email(data.email, db) is not None

    # Sin cuenta y con una contraseña inicial: se crea la cuenta con esa contraseña y en su primer ingreso tiene que
    # cambiarla. La que define el administrador que da de alta nunca queda como la definitiva.
    initial = data.initial_password if not already_has_password else None
    if initial is not None:
        error = password_rule_error(initial)
        if error:
            raise HTTPException(status_code=400, detail=error)
        db.add(User(email=data.email, hashed_password=hash_password(initial), must_change_password=True))
    admin = AdminUser(
        email=data.email, full_name=data.full_name, password_set=already_has_password or initial is not None
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)

    response = AdminResponse.model_validate(admin)
    if not already_has_password and initial is None:
        # Quien da de alta se lo hace llegar: es lo único que le permite definir su contraseña.
        response.invite_token = create_admin_invite_token(admin.email)
    return response
