from datetime import datetime
from enum import StrEnum
from typing import Any

from app.services.exceptions import ValidationError


def require_non_blank(value: Any, field_name: str) -> str:
    """Ensure a value is a string containing non-whitespace characters."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"Поле '{field_name}' обязательно и не может быть пустым")
    return value.strip()


def require_positive_int(value: Any, field_name: str) -> int:
    """Ensure a value is a non-boolean positive integer."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValidationError(f"Поле '{field_name}' должно быть положительным целым числом")
    return value


def require_iso_datetime(value: Any, field_name: str) -> str:
    """Ensure a value is a non-blank valid ISO-8601 date/datetime string."""
    cleaned = require_non_blank(value, field_name)
    try:
        datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise ValidationError(
            f"Поле '{field_name}' должно быть корректной датой/временем в формате ISO-8601"
        ) from exc
    return cleaned


def require_non_blank_enum_input(
    value: Any,
    enum_cls: type[StrEnum],
    field_name: str,
) -> Any:
    """Ensure enum input is either an instance of enum_cls or a non-blank string."""
    if isinstance(value, enum_cls):
        return value
    return require_non_blank(value, field_name)
