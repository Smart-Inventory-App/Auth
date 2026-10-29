import os
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_auth.db")
os.environ.setdefault("JWT_SECRET", "test-secret")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, get_db
from app.main import app

TEST_DB_URL = "sqlite:///./test_auth.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def sin_smtp_real(monkeypatch):
    """Ningún test manda mails de verdad, aunque el .env de quien corre los tests tenga el SMTP configurado."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "SMTP_HOST", "")
    monkeypatch.setattr(settings, "SMTP_USER", "")


@pytest.fixture
def db():
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


VALID_PASSWORD = "Patronus.3"
TEST_EMAIL = "test@example.com"


def register_user(client, email=TEST_EMAIL, password=VALID_PASSWORD):
    return client.post("/auth/register", json={"email": email, "password": password})


def create_admin(db, email="admin@example.com", full_name=None, is_active=True, password_set=False):
    from app.models.admin import AdminUser

    admin = AdminUser(email=email, full_name=full_name, is_active=is_active, password_set=password_set)
    db.add(admin)
    db.commit()
    db.refresh(admin)
    return admin


def admin_token(email: str) -> str:
    from jose import jwt

    from app.core.config import settings

    return jwt.encode({"email": email}, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
