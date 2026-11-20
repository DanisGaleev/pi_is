import secrets
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from app.container import container
from app.domain.models import User
from app.enums import Role
from app.repositories.sqlite_repo import hash_password, utc_now

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


def _parse_role(value: Role | str) -> Role | str:
    if isinstance(value, Role):
        return value
    try:
        return Role(value)
    except ValueError:
        return value


def _user_dict(user: User | Any) -> dict[str, Any]:
    if isinstance(user, User):
        return {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "role": _parse_role(user.role),
        }
    return {
        "id": user["id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "role": _parse_role(user["role"]),
    }


def get_current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Неверный токен")

    user = container.session_repo.get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Сессия не найдена")
    return _user_dict(user)


@router.post("/login")
def login(payload: LoginRequest) -> dict[str, Any]:
    user = container.auth_provider.authenticate(payload.username, payload.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")

    token = secrets.token_hex(24)
    container.session_repo.create(token, user.id, utc_now())
    return {"token": token, "user": _user_dict(user)}


@router.get("/me")
def me(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return user


__all__ = [
    "LoginRequest",
    "get_current_user",
    "hash_password",
    "login",
    "me",
    "router",
]
