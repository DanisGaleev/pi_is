import hashlib
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from app.enums import Role
from db import get_conn, utc_now

router = APIRouter(prefix="/api/auth", tags=["auth"])


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


class LoginRequest(BaseModel):
    username: str
    password: str


def _parse_role(value: str) -> Role | str:
    try:
        return Role(value)
    except ValueError:
        return value


def _user_dict(row) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "full_name": row["full_name"],
        "role": _parse_role(row["role"]),
    }


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Неверный токен")

    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.full_name, u.role
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise HTTPException(status_code=401, detail="Сессия не найдена")
    return _user_dict(row)


@router.post("/login")
def login(payload: LoginRequest) -> dict:
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT id, username, password_hash, full_name, role FROM users WHERE username = ?",
            (payload.username,),
        ).fetchone()
        if row is None or row["password_hash"] != hash_password(payload.password):
            raise HTTPException(status_code=401, detail="Неверный логин или пароль")

        token = secrets.token_hex(24)
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
            (token, row["id"], utc_now()),
        )
        conn.commit()
        return {"token": token, "user": _user_dict(row)}
    finally:
        conn.close()


@router.get("/me")
def me(user: dict = Depends(get_current_user)) -> dict:
    return user
