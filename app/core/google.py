"""Verificación de los idToken de Google.

La app le manda al servidor el `idToken` que Google le dio al usuario. Se verifica acá, sin llamar a Google por cada
login: la firma se comprueba con las claves públicas de Google (que se guardan un rato en memoria), y se exige que
el token haya sido emitido **para nuestra app** (campo `aud`). Sin ese control, un token de Google emitido a cualquier
otra aplicación serviría para entrar como esa persona.
"""
import time

import httpx
from jose import JWTError, jwt

GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}
# Las claves de Google rotan cada tanto: se vuelven a pedir pasada una hora (o antes, si llega un token con una clave nueva)
CERTS_CACHE_SECONDS = 3600
# Margen por si el reloj del servidor y el de Google no coinciden del todo
CLOCK_SKEW_SECONDS = 30


class GoogleTokenError(Exception):
    """El token no es válido: firma, vencimiento, emisor o app para la que fue emitido."""


class GoogleUnreachable(Exception):
    """No se pudieron obtener las claves de Google."""


_certs = {"keys": [], "fetched_at": 0.0}


def reset_certs_cache() -> None:
    _certs["keys"] = []
    _certs["fetched_at"] = 0.0


def _google_keys(force: bool = False) -> list[dict]:
    fresh = _certs["keys"] and time.time() - _certs["fetched_at"] < CERTS_CACHE_SECONDS
    if fresh and not force:
        return _certs["keys"]
    try:
        response = httpx.get(GOOGLE_CERTS_URL, timeout=10)
    except httpx.RequestError:
        raise GoogleUnreachable()
    if response.status_code != 200:
        raise GoogleUnreachable()
    _certs["keys"] = response.json().get("keys", [])
    _certs["fetched_at"] = time.time()
    return _certs["keys"]


def _key_for(kid: str | None) -> dict | None:
    for key in _google_keys():
        if key.get("kid") == kid:
            return key
    # Puede ser una clave nueva que todavía no teníamos guardada
    for key in _google_keys(force=True):
        if key.get("kid") == kid:
            return key
    return None


def verify_google_id_token(id_token: str, client_ids: list[str]) -> dict:
    """Devuelve los datos (claims) del token si es válido y fue emitido para alguno de `client_ids`."""
    try:
        header = jwt.get_unverified_header(id_token)
    except JWTError:
        raise GoogleTokenError("token mal formado")
    # Google firma con RS256: aceptar otro algoritmo permitiría falsificar el token
    if header.get("alg") != "RS256":
        raise GoogleTokenError("algoritmo no permitido")

    key = _key_for(header.get("kid"))
    if key is None:
        raise GoogleTokenError("clave desconocida")

    try:
        claims = jwt.decode(
            id_token,
            key,
            algorithms=["RS256"],
            # La audiencia y el emisor se comprueban abajo: Google usa dos formas para el emisor y el servidor
            # puede aceptar varios client ID.
            options={"verify_aud": False, "verify_iss": False, "verify_at_hash": False, "leeway": CLOCK_SKEW_SECONDS},
        )
    except JWTError as exc:
        raise GoogleTokenError(str(exc))

    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else list(audience or [])
    if not set(audiences) & set(client_ids):
        raise GoogleTokenError("el token no fue emitido para esta app")
    if claims.get("iss") not in GOOGLE_ISSUERS:
        raise GoogleTokenError("emisor inválido")
    return claims
