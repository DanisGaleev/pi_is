from collections.abc import Callable
from typing import Any, TypeVar

from fastapi import HTTPException

from app.services.exceptions import ServiceError

T = TypeVar("T")


def call_service(fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Invoke a service method and translate domain/service errors into HTTPException."""
    try:
        return fn(*args, **kwargs)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
