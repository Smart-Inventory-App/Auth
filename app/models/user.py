import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class User(Base):
    __tablename__ = "auth_users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    firebase_token = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    # False para las cuentas creadas por /auth/google la primera vez: tienen un
    # hash aleatorio que nadie conoce. forgot-password usa este flag para
    # mandar el mail de "configurá tu contraseña" en vez de "recuperala", y
    # reset-password lo pone en True apenas definen una real.
    has_password = Column(Boolean, default=True, nullable=False)


class PasswordResetCode(Base):
    __tablename__ = "auth_password_reset_codes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("auth_users.id"), nullable=False)
    code = Column(String(6), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
