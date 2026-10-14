# Auth — Smart Inventory Platform

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
| POST | `/auth/register` | Crear cuenta (email + contraseña) | — |
| POST | `/auth/login` | Login → devuelve `access_token` | — |
| POST | `/auth/check-email` | Verificar si un email ya existe | — |
| POST | `/auth/google` | Login con Google OAuth | — |
| GET  | `/auth/me` | Info del usuario autenticado | Bearer |

### Recuperación de Contraseña

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | `/auth/forgot-password` | Envía código de 6 dígitos por email |
| POST | `/auth/verify-code` | Valida código → devuelve `reset_token` |
| POST | `/auth/reset-password` | Cambia la contraseña con el `reset_token` |

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
| `auth.invalid_or_expired_code` | Código expirado |
| `auth.invalid_or_expired_token` | Reset token inválido o expirado |
| `auth.google_unreachable` | No se pudo contactar a Google |
| `auth.google_invalid_token` | Token de Google inválido |
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
# Compartido con el resto de los servicios; vacío = /auth/admin/whitelist cerrado
INTERNAL_SERVICE_TOKEN=
DEBUG=true

# SMTP (vacío = solo loguea el código en consola)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=noreply@smartinventory.com
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
│   │   ├── email.py        # Envío SMTP de código de recuperación
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
| `auth_users` | Usuarios (id UUID, email, hashed_password, is_active) |
| `auth_password_reset_codes` | Códigos de 6 dígitos para recuperación de contraseña |

---

## Flujo de Recuperación de Contraseña

```
POST /auth/forgot-password  →  genera código de 6 dígitos → envía por email
POST /auth/verify-code      →  valida código → devuelve reset_token (JWT 15 min)
POST /auth/reset-password   →  valida reset_token → actualiza hashed_password
```
