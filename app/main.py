from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import Base, engine
from app.models import admin, user  # noqa: F401 — registra modelos
from app.routes.admin import router as admin_router
from app.routes.auth import router

# Tabla `admin_users`: puede ya existir (creada antes por el backoffice) en la
# misma base compartida — create_all es aditivo, no la toca si ya está.
Base.metadata.create_all(bind=engine)

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
