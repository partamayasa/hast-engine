# backend/routers/deps.py
"""Dependency FastAPI: sesi basis data dan pengguna terautentikasi."""
from collections.abc import Iterator
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from backend.core.roles import ROLES, has_permission, permissions_of
from backend.core.security import decode_access_token
from backend.db.session import get_sessionmaker
from backend.repositories import users as users_repo

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_db(request: Request) -> Iterator[Session]:
    session = get_sessionmaker(request.app.state.database_url)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@dataclass
class CurrentUser:
    username: str
    role: str
    full_name: str | None = None

    @property
    def is_manager(self) -> bool:
        return self.role in ("manager", "admin")

    @property
    def permissions(self) -> set[str]:
        return permissions_of(self.role)

    def can(self, permission: str) -> bool:
        return has_permission(self.role, permission)


def get_optional_user(token: str | None = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> CurrentUser | None:
    if not token:
        return None
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        return None
    user = users_repo.get_by_username(db, payload.get("sub", ""))
    if user is None or not user.is_active:
        return None
    return CurrentUser(username=user.username, role=user.role, full_name=user.full_name)


def get_current_user(user: CurrentUser | None = Depends(get_optional_user)) -> CurrentUser:
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autentikasi diperlukan. Silakan login terlebih dahulu.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_permission(permission: str):
    """Factory dependency: pemanggil harus sudah login dan memiliki hak `permission`."""
    def _dep(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not user.can(permission):
            label = ROLES.get(user.role, {}).get("label", user.role)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"Role {label} tidak memiliki hak untuk aksi ini.")
        return user
    return _dep


# Alias kompatibel mundur (v2.0): hak "manager" kini berarti hak pengaturan prioritas.
require_manager = require_permission("settings.manage")
