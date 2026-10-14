"""Alta de un administrador (whitelist).

Agrega el email a la whitelist de administradores (`admin_users`) e imprime el
código de invitación con el que el propio admin define su contraseña en su
primer inicio de sesión (POST /auth/admin/set-password). Sin ese código nadie
puede definirla. Si el admin ya existe y sigue pendiente, imprime un código
nuevo (el anterior vence a los ADMIN_INVITE_EXPIRE_HOURS).

Uso:
    python create_admin.py <email> "<Nombre Apellido>"

Sin argumentos crea un admin por defecto:
    admin@smartinventory.com
"""
import sys

from app.core.database import Base, SessionLocal, engine
from app.core.security import create_admin_invite_token
from app.models.admin import AdminUser


def main():
    Base.metadata.create_all(bind=engine)

    if len(sys.argv) >= 2:
        email = sys.argv[1]
        full_name = sys.argv[2] if len(sys.argv) >= 3 else None
    else:
        email = "admin@smartinventory.com"
        full_name = "Administrador"
        print("No se pasaron argumentos: usando admin por defecto.")

    db = SessionLocal()
    try:
        existing = db.query(AdminUser).filter(AdminUser.email == email).first()
        if existing:
            if existing.password_set:
                print(f"Ya existe un administrador con el email {email}. No se creó nada.")
                return
            print(f"El administrador {email} sigue pendiente de definir su contraseña.")
        else:
            admin = AdminUser(email=email, full_name=full_name, password_set=False)
            db.add(admin)
            db.commit()
            print(f"Administrador agregado a la whitelist: {email}")
        print("Código de invitación (pasáselo solo a esa persona; lo pide al definir su contraseña):")
        print(create_admin_invite_token(email))
    finally:
        db.close()


if __name__ == "__main__":
    main()
