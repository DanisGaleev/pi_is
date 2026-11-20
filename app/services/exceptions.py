from collections.abc import Mapping
from typing import Any

from app.domain.models import User


class ServiceError(Exception):
    """Base application service error mapped to HTTP status codes by routers."""

    status_code: int = 400

    def __init__(self, detail: str, status_code: int | None = None) -> None:
        super().__init__(detail)
        self.detail = detail
        if status_code is not None:
            self.status_code = status_code


class UnauthorizedError(ServiceError, PermissionError):
    """Authentication failure (HTTP 401)."""

    status_code: int = 401


class AccessDeniedError(ServiceError, PermissionError):
    """Authorization / RBAC denial (HTTP 403)."""

    status_code: int = 403


class NotFoundError(ServiceError, LookupError):
    """Requested entity does not exist (HTTP 404)."""

    status_code: int = 404


class ValidationError(ServiceError, ValueError):
    """Invalid input or malformed external payload (HTTP 400)."""

    status_code: int = 400


def coerce_user(user: User | Mapping[str, Any]) -> User:
    """Normalize a domain User or user dictionary into a User instance."""
    if isinstance(user, User):
        return user
    return User(
        id=int(user["id"]),
        username=str(user.get("username", "")),
        full_name=str(user.get("full_name", "")),
        role=user["role"],
        active=bool(user.get("active", True)),
    )
