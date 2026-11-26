# backend/repositories/users.py
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.core.security import ROLES, hash_password, verify_password
from backend.db.models import User


def count_users(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(User)) or 0


def get_by_username(session: Session, username: str) -> User | None:
    return session.scalar(select(User).where(User.username == username))


def list_users(session: Session) -> list[User]:
    return list(session.scalars(select(User).order_by(User.id)))


def create_user(session: Session, username: str, password: str, role: str = "analyst",
                full_name: str | None = None) -> User:
    username = username.strip()
    if role not in ROLES:
        raise ValueError(f"Role tidak dikenal: {role}. Pilihan: {', '.join(ROLES)}")
    if len(password) < 8:
        raise ValueError("Password minimal 8 karakter.")
    if get_by_username(session, username):
        raise ValueError(f"Username '{username}' sudah terdaftar.")
    user = User(username=username, password_hash=hash_password(password), role=role,
                full_name=full_name, is_active=True)
    session.add(user)
    session.flush()
    return user


def authenticate(session: Session, username: str, password: str) -> User | None:
    user = get_by_username(session, username.strip())
    if user and user.is_active and verify_password(password, user.password_hash):
        return user
    return None


def set_password(session: Session, user: User, new_password: str) -> None:
    if len(new_password) < 8:
        raise ValueError("Password minimal 8 karakter.")
    user.password_hash = hash_password(new_password)


def count_active_admins(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(User)
                          .where(User.role == "admin", User.is_active.is_(True))) or 0


def update_user(session: Session, username: str, actor: str, role: str | None = None,
                is_active: bool | None = None, full_name: str | None = None) -> User:
    """Mengubah peran / status aktif / nama. Pengaman: Administrator aktif terakhir tidak pernah hilang, dan pengguna tidak dapat menonaktifkan dirinya sendiri."""
    user = get_by_username(session, username)
    if user is None:
        raise LookupError(f"User '{username}' tidak ditemukan.")
    if role is not None and role not in ROLES:
        raise ValueError(f"Role tidak dikenal: {role}.")
    if is_active is False and username == actor:
        raise ValueError("Anda tidak dapat menonaktifkan akun Anda sendiri.")
    losing_admin = user.role == "admin" and user.is_active and (
        (role is not None and role != "admin") or is_active is False)
    if losing_admin and count_active_admins(session) <= 1:
        raise ValueError("Harus tersisa minimal satu Administrator aktif.")
    if role is not None:
        user.role = role
    if is_active is not None:
        user.is_active = is_active
    if full_name is not None:
        user.full_name = full_name.strip() or None
    session.flush()
    return user
