# backend/routers/v1/auth.py
"""Login (alur OAuth2 password + JWT), katalog peran, dan manajemen pengguna (kendali akses berbasis peran)."""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.core.roles import PERMISSIONS, ROLES, permissions_of, role_catalog
from backend.core.security import create_access_token
from backend.repositories import users as users_repo
from backend.routers.deps import CurrentUser, get_current_user, get_db, require_permission

router = APIRouter(prefix="/api/v1", tags=["Autentikasi"])


def _user_dict(username: str, role: str, full_name: str | None, is_active: bool | None = None) -> dict:
    out = {"username": username, "role": role, "role_label": ROLES.get(role, {}).get("label", role),
           "full_name": full_name, "permissions": sorted(permissions_of(role))}
    if is_active is not None:
        out["is_active"] = is_active
    return out


@router.post("/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = users_repo.authenticate(db, form.username, form.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Username atau password salah.")
    return {
        "access_token": create_access_token(user.username, user.role),
        "token_type": "bearer",
        "user": _user_dict(user.username, user.role, user.full_name),
    }


@router.get("/auth/me")
def me(user: CurrentUser = Depends(get_current_user)):
    return _user_dict(user.username, user.role, user.full_name)


@router.get("/roles")
def roles():
    """Katalog peran (publik): label, deskripsi, dan hak akses untuk mengisi dropdown peran."""
    return {"roles": role_catalog(), "permissions": PERMISSIONS}


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="analyst")
    full_name: str | None = Field(default=None, max_length=128)


class UserUpdate(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    full_name: str | None = Field(default=None, max_length=128)


@router.get("/users")
def list_users(db: Session = Depends(get_db), _a: CurrentUser = Depends(require_permission("users.manage"))):
    return {"users": [_user_dict(u.username, u.role, u.full_name, u.is_active) for u in users_repo.list_users(db)]}


@router.post("/users", status_code=201)
def create_user(data: UserCreate, db: Session = Depends(get_db),
                _a: CurrentUser = Depends(require_permission("users.manage"))):
    if data.role not in ROLES:
        raise HTTPException(status_code=422, detail=f"Role harus salah satu dari: {', '.join(ROLES)}")
    try:
        u = users_repo.create_user(db, data.username, data.password, data.role, data.full_name)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return _user_dict(u.username, u.role, u.full_name, u.is_active)


@router.patch("/users/{username}")
def update_user(username: str, data: UserUpdate, db: Session = Depends(get_db),
                actor: CurrentUser = Depends(require_permission("users.manage"))):
    try:
        u = users_repo.update_user(db, username, actor.username, role=data.role, is_active=data.is_active,
                                   full_name=data.full_name)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return _user_dict(u.username, u.role, u.full_name, u.is_active)
