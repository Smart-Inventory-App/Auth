from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.core.database import Base, engine
from app.models import admin, user  # noqa: F401 — registra modelos
from app.routes.admin import router as admin_router
from app.routes.auth import router

# Tabla `admin_users`: puede ya existir (creada antes por el backoffice) en la
# misma base compartida — create_all es aditivo, no la toca si ya está.
Base.metadata.create_all(bind=engine)

# create_all no altera tablas existentes: no hay Alembic en este servicio, así
# que las columnas nuevas sobre tablas preexistentes en producción se agregan
# acá a mano, de forma idempotente. Las cuentas que ya existían quedan con el
# valor por defecto (contraseña definida, mail verificado). En SQLite (tests) las
# columnas ya vienen incluidas porque las tablas se crean de cero con el modelo.
COLUMN_MIGRATIONS = [
    "ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS has_password BOOLEAN NOT NULL DEFAULT TRUE",
    "ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE auth_password_reset_codes ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0",
]


def apply_column_migrations(bind=engine):
    if bind.dialect.name != "postgresql":
        return
    with bind.begin() as conn:
        for statement in COLUMN_MIGRATIONS:
            conn.execute(text(statement))


apply_column_migrations()

app = FastAPI(title="Auth Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.include_router(admin_router)


@app.get("/health")
def health():
    return {"status": "ok"}
