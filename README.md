# Auth — Smart Inventory Platform

<p align="center"><img src="assets/brand/logo_horizontal_color.png" alt="Smart Inventory" width="360"></p>

[![codecov](https://codecov.io/gh/Smart-Inventory-App/Auth/branch/main/graph/badge.svg?token=rBIEPB69rA)](https://codecov.io/gh/Smart-Inventory-App/Auth)

Microservicio de autenticación para Smart Inventory. Gestiona registro, login (email/contraseña y Google OAuth), recuperación de contraseña y emisión de JWT.

---

## Stack

- Python 3.11 + FastAPI
- PostgreSQL (SQLAlchemy + Alembic)
- JWT HS256 (python-jose)
- bcrypt (passlib)
- SMTP para envío de códigos de recuperación

---

## Endpoints

### Autenticación

| Método | Endpoint | Descripción | Auth |
|--------|----------|-------------|------|
| POST | `/auth/register` | Crear cuenta (email + contraseña). Manda el mail de bienvenida | — |
| POST | `/auth/login` | Login → devuelve `access_token` | — |
| POST | `/auth/check-email` | Verificar si un email ya existe | — |
| POST | `/auth/google` | Login con Google: recibe el `id_token` de Google, lo verifica y devuelve `access_token` | — |
| GET  | `/auth/me` | Info del usuario autenticado | Bearer |

### Recuperación de Contraseña

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | `/auth/forgot-password` | Envía código de 6 dígitos por email |
| POST | `/auth/verify-code` | Valida código → devuelve `reset_token` |
| POST | `/auth/reset-password` | Cambia la contraseña con el `reset_token` |

### Login con Google

La app manda el **`id_token`** que Google le dio al usuario (`POST /auth/google` con `{ "id_token": "..." }`). El servicio **lo verifica por su cuenta**, sin llamar a Google en cada login (`app/core/google.py`):

- **Firma:** se comprueba con las claves públicas de Google (`https://www.googleapis.com/oauth2/v3/certs`), que se guardan una hora en memoria y se vuelven a pedir si llega un token firmado con una clave nueva. Solo se acepta el algoritmo `RS256`.
- **Vencimiento** del token (con 30 segundos de margen por diferencias de reloj).
- **Emisor** (`accounts.google.com`).
- **Para quién se emitió** (`aud`): tiene que ser alguno de los IDs de `GOOGLE_CLIENT_ID`. Sin este control, un token de Google emitido a cualquier otra aplicación serviría para entrar como esa persona.
- **Email verificado** por Google.

Si el email no tiene cuenta, se crea una con una contraseña aleatoria que nadie conoce y `has_password = false`: la persona puede definir una propia con «Olvidé mi contraseña», que en ese caso manda el mail de «Configurá tu contraseña». Si ya tenía cuenta, se entra en ella.

**Mail de bienvenida.** Al crear la cuenta, ya sea con `/auth/register` o la primera vez que alguien entra con Google, se manda un mail de bienvenida con los primeros pasos (cargar productos, inventario, alertas, notificaciones). Se envía después de responder, así que no demora el alta, y si falla no la impide (queda en el log). Entrar de nuevo con Google, o con Google a una cuenta ya registrada, no lo repite. Los mails (bienvenida, código de recuperación y «Configurá tu contraseña») llevan el logo si `EMAIL_LOGO_URL` está definida.

**Cuentas registradas con contraseña.** Si el email ya tenía una cuenta creada con `/auth/register`, entrar con Google **conserva su contraseña**: la persona puede ingresar con Google o con su contraseña de siempre.
`GOOGLE_CLIENT_ID` es el ID del cliente de tipo **Aplicación web** de Google Cloud (el mismo que usa la app como `webClientId`). Se pueden poner varios separados por comas. **Vacío = el login con Google queda deshabilitado** (`503 auth.google_not_configured`).

---

### Administradores (whitelist del backoffice)

Este servicio es el dueño de la tabla `admin_users`. Las credenciales viven en `auth_users`, igual que para cualquier usuario; la tabla solo dice **qué emails son admin**.

| Método | Endpoint | Descripción | Auth |
|--------|----------|-------------|------|
| POST | `/auth/admin/check` | Paso 1 del login: `exists` / `is_admin` / `password_set` (público, no devuelve el nombre) | — |
| POST | `/auth/admin/set-password` | Un admin pendiente define su primera contraseña. **Exige `invite_token`** | Código de invitación |
| POST | `/auth/admin/login` | Login de admin (whitelist + contraseña ya definida) | — |
| GET | `/auth/admin/admins` | Lista de admins | Bearer de admin |
| POST | `/auth/admin/admins` | Alta de admin. Si el email todavía no tiene cuenta, la respuesta trae `invite_token` | Bearer de admin |
| GET | `/auth/admin/whitelist?email=` | Estado crudo de la whitelist, para otros servicios | `X-Internal-Token` |

**Código de invitación.** Un admin pendiente (sin contraseña) solo puede definirla con el código que se genera al darlo de alta: es un JWT firmado con `JWT_SECRET`, atado a su email, que vence a las `ADMIN_INVITE_EXPIRE_HOURS` (168 por defecto) y deja de servir apenas se define la contraseña. Si el email ya tenía una cuenta creada después de entrar a la whitelist, la contraseña que define el invitado **reemplaza** a la existente (el registro público no verifica el correo, así que nadie puede adelantarse y heredar el rol). No se guarda en la base y no sirve como token de acceso en ningún servicio. Sin él, saber el email de un admin pendiente no alcanza para quedarse con la cuenta.

**Primer admin.** Se da de alta por línea de comandos; imprime el código para pasárselo a esa persona (volver a correrlo para un admin pendiente imprime uno nuevo):

```bash
python create_admin.py mail@dominio.com "Nombre Apellido"
```

**`INTERNAL_SERVICE_TOKEN`** protege `/auth/admin/whitelist` (mismo valor que usan `app_backend`, `backoffice_backend` y `ml`). Si no está configurado, ese endpoint queda cerrado para todos.

---

## Validaciones de Contraseña

`/auth/register` y `/auth/reset-password` exigen:
- Mínimo 8 caracteres
- Al menos una mayúscula
- Al menos una minúscula
- Al menos un número

---

## Códigos de Error

Todos los errores devuelven un código i18n en el campo `detail` para que el frontend traduzca:

| Código | Situación |
|--------|-----------|
| `auth.password_too_short` | Contraseña menor a 8 caracteres |
| `auth.password_missing_uppercase` | Sin mayúscula |
| `auth.password_missing_lowercase` | Sin minúscula |
| `auth.password_missing_digit` | Sin número |
| `auth.email_already_registered` | Email duplicado |
| `auth.invalid_credentials` | Email o contraseña incorrectos |
| `auth.account_disabled` | Cuenta desactivada |
| `auth.invalid_code` | Código de recuperación inválido |
| `auth.invalid_or_expired_code` | Código expirado, ya usado o incorrecto |
| `auth.too_many_attempts` | (429) 5 intentos fallidos de código: el código se invalidó, hay que pedir uno nuevo |
| `auth.invalid_or_expired_token` | Reset token inválido o expirado |
| `auth.google_not_configured` | El servidor no tiene `GOOGLE_CLIENT_ID` |
| `auth.google_unreachable` | No se pudieron obtener las claves de Google |
| `auth.google_invalid_token` | Token de Google inválido, vencido o emitido para otra app |
| `auth.google_email_not_verified` | Email de Google no verificado |
| `auth.invalid_token` | JWT inválido |
| `auth.user_not_found` | Usuario no encontrado |

---

## JWT

El `access_token` contiene:

```json
{ "sub": "<user_uuid>", "email": "<email>", "exp": "<timestamp>" }
```

- Algoritmo: **HS256**
- Expiración: **30 minutos** (configurable)
- El mismo `JWT_SECRET` debe compartirse con `App_backend` e `image_storage_service`

---

## Configuración

Crear `.env` a partir de `.env.example`:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/tpp_db
JWT_SECRET=change-this-secret-in-production
JWT_ALGORITHM=HS256
JWT_ACCESS_EXPIRE_MINUTES=30
JWT_RESET_EXPIRE_MINUTES=15
ADMIN_INVITE_EXPIRE_HOURS=168
# ID de cliente «Aplicación web» de Google Cloud (varios, separados por comas). Vacío = login con Google deshabilitado
GOOGLE_CLIENT_ID=
# Compartido con el resto de los servicios; vacío = /auth/admin/whitelist cerrado
INTERNAL_SERVICE_TOKEN=
# true solo en desarrollo: forgot-password devuelve el código en la respuesta (`debug_code`). Por defecto false
DEBUG=false

# SMTP (vacío = solo loguea el código en consola)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=noreply@smartinventory.com

# Logo de los mails: URL https pública del archivo que sirve la web de app_frontend (public/email-logo.png),
EMAIL_LOGO_URL=
```

---

## Setup Local

```bash
python -m venv venv
source .venv/bin/activate
pip install -r requirements.txt

# Aplicar migraciones
alembic upgrade head

# Levantar
uvicorn app.main:app --reload --port 8001
```

Swagger disponible en `http://localhost:8001/docs`.

---

## Docker

```bash
# Build y run
docker build -t tpp_auth .
docker run --env-file .env -p 8001:8000 tpp_auth

# O con compose (requiere red tpp-net creada)
docker network create tpp-net
docker-compose up -d
```

---

## Estructura

```
Auth/
├── app/
│   ├── core/
│   │   ├── config.py       # Settings (pydantic-settings)
│   │   ├── database.py     # Engine + sesión SQLAlchemy
│   │   ├── email.py        # Envío SMTP: bienvenida y códigos de recuperación
│   │   └── security.py     # Hash bcrypt, creación/validación JWT
│   ├── models/
│   │   └── user.py         # User + PasswordResetCode
│   ├── routes/
│   │   └── auth.py         # Todos los endpoints /auth/*
│   └── schemas/
│       └── auth.py         # Pydantic request/response schemas
├── alembic/                # Migraciones
├── docker-compose.yml
├── Dockerfile
└── .env.example
```

---

## Tablas

| Tabla | Descripción |
|-------|-------------|
| `auth_users` | Usuarios (id UUID, email, hashed_password, is_active, has_password) |
| `auth_password_reset_codes` | Códigos de 6 dígitos para recuperación de contraseña (con `failed_attempts`) |

Las columnas nuevas sobre tablas existentes se agregan al iniciar el servicio con `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (`apply_column_migrations` en `app/main.py`).

---

## Flujo de Recuperación de Contraseña

```
POST /auth/forgot-password  →  genera código de 6 dígitos → envía por email
POST /auth/verify-code      →  valida código → devuelve reset_token (JWT 15 min)
POST /auth/reset-password   →  valida reset_token → actualiza hashed_password
```
