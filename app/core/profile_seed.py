"""El perfil de una cuenta que se crea con Google arranca con el nombre y el apellido de esa cuenta de Google.

Pasa **solo al crearse la cuenta** (volver a entrar con Google no toca nada, y si la persona después cambia su nombre en el
perfil, ese cambio manda). El perfil lo dibujan la app del celular y el dashboard, que comparten la tabla `user_profiles`
(la crea `app_backend`): acá se deja la fila ya con el nombre, y ellos la encuentran cuando la necesitan.

Es de mejor esfuerzo: si la tabla todavía no existe o la escritura falla, la cuenta se crea igual y la persona completa su
nombre a mano, como antes.
"""
import logging

from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# El mismo tope que valida el perfil de la app para el nombre y el apellido
NAME_MAX = 20


def _clean(value) -> str | None:
    text_value = " ".join(str(value).split()) if value else ""
    return text_value[:NAME_MAX].rstrip() or None


def names_from_claims(claims: dict) -> tuple[str | None, str | None]:
    """Nombre y apellido de la cuenta de Google: `given_name` y `family_name`; si Google solo manda `name`, la primera
    palabra es el nombre y el resto el apellido."""
    first, last = _clean(claims.get("given_name")), _clean(claims.get("family_name"))
    if not first and not last:
        parts = " ".join(str(claims.get("name") or "").split()).split(" ", 1)
        first, last = _clean(parts[0]), _clean(parts[1] if len(parts) > 1 else None)
    return first, last


def seed_profile_names(db: Session, user_id: str, claims: dict) -> bool:
    """Crea el perfil del usuario nuevo con su nombre y apellido de Google. Devuelve si lo creó."""
    first, last = names_from_claims(claims)
    if not first and not last:
        return False
    try:
        if not inspect(db.get_bind()).has_table("user_profiles"):
            return False
        db.execute(
            text(
                "INSERT INTO user_profiles (user_id, first_name, last_name) VALUES (:user_id, :first, :last) "
                "ON CONFLICT (user_id) DO NOTHING"
            ),
            {"user_id": user_id, "first": first, "last": last},
        )
        db.commit()
        return True
    except SQLAlchemyError:
        db.rollback()
        logger.warning("No se pudo guardar el nombre de Google en el perfil de %s", user_id, exc_info=True)
        return False
