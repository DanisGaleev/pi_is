from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, BeforeValidator, ValidationInfo, field_validator, model_validator

from app.container import container
from app.enums import (
    IncidentStatus,
    IncidentType,
    PdnFlag,
    Severity,
    SourceType,
)
from app.repositories.sqlite_repo import (
    DEFAULT_INCIDENT_SORT_BY,
    DEFAULT_INCIDENT_SORT_ORDER,
)
from app.services.exceptions import ValidationError
from app.services.incidents import normalize_outcome
from app.services.validators import (
    optional_iso_datetime,
    optional_text,
    require_non_blank,
    require_non_blank_enum_input,
)
from auth import get_current_user
from routers import call_service

router = APIRouter(prefix="/api", tags=["incidents"])


def _normalize_signal_source(raw: str | SourceType | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, SourceType):
        return raw.value
    if not str(raw).strip():
        return ""
    return SourceType.normalize(raw).value


def _normalize_required_incident_type(raw: Any) -> IncidentType:
    checked = require_non_blank_enum_input(raw, IncidentType, "incident_type")
    return IncidentType.normalize(checked)


def _normalize_required_source_type(raw: Any) -> SourceType:
    checked = require_non_blank_enum_input(raw, SourceType, "source")
    return SourceType.normalize(checked)


NormalizedIncidentType = Annotated[IncidentType, BeforeValidator(IncidentType.normalize)]
RequiredIncidentType = Annotated[IncidentType, BeforeValidator(_normalize_required_incident_type)]
NormalizedSeverity = Annotated[Severity, BeforeValidator(Severity.normalize)]
NormalizedIncidentStatus = Annotated[IncidentStatus, BeforeValidator(IncidentStatus.normalize)]
NormalizedSourceType = Annotated[SourceType, BeforeValidator(SourceType.normalize)]
RequiredSourceType = Annotated[SourceType, BeforeValidator(_normalize_required_source_type)]
SignalSource = Annotated[str, BeforeValidator(_normalize_signal_source)]
NormalizedOutcome = Annotated[str | None, BeforeValidator(normalize_outcome)]


class IncidentCreate(BaseModel):
    title: str
    description: str = ""
    incident_type: RequiredIncidentType
    severity: NormalizedSeverity = Severity.MEDIUM
    computer: str = ""
    employee: str = ""
    source: RequiredSourceType
    incident_key: str = ""
    has_personal_data: bool | int | PdnFlag = 0
    instruction_id: int | None = None
    detected_at: str | None = None

    @field_validator("title", mode="before")
    @classmethod
    def _validate_title(cls, value: Any) -> str:
        return require_non_blank(value, "title")

    @field_validator("description", "computer", "employee", "incident_key", mode="before")
    @classmethod
    def _validate_optional_text(cls, value: Any, info: ValidationInfo) -> str:
        return optional_text(value, info.field_name or "field")

    @field_validator("severity", mode="before")
    @classmethod
    def _default_optional_severity(cls, value: Any) -> Any:
        if value is None or (isinstance(value, str) and not value.strip()):
            return Severity.MEDIUM
        return value

    @field_validator("detected_at", mode="before")
    @classmethod
    def _validate_detected_at(cls, value: Any) -> str | None:
        return optional_iso_datetime(value, "detected_at")


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    incident_type: NormalizedIncidentType | None = None
    severity: NormalizedSeverity | None = None
    has_personal_data: bool | int | PdnFlag | None = None
    instruction_id: int | None = None
    rkn_draft: str | None = None


class StatusTransition(BaseModel):
    status: NormalizedIncidentStatus
    outcome: NormalizedOutcome = None

    @model_validator(mode="after")
    def _validate_closed_outcome(self) -> "StatusTransition":
        if self.status is IncidentStatus.CLOSED:
            if self.outcome is not None and not self.outcome.strip():
                raise ValidationError("Для закрытия инцидента поле 'outcome' не может быть пустым")
        return self


class SignalIn(BaseModel):
    source: SignalSource = ""
    sender: str = ""
    body: str
    computer: str = ""
    employee: str = ""
    incident_type: NormalizedIncidentType | None = None
    severity: NormalizedSeverity | None = None
    incident_key: str = ""
    has_personal_data: bool | int | PdnFlag = 0
    title: str | None = None
    error_code: str = ""
    assigned_to: int | None = None

    @field_validator("body", mode="before")
    @classmethod
    def _validate_body(cls, value: Any) -> str:
        return require_non_blank(value, "body")


@router.get("/incidents")
def list_incidents(
    q: str | None = None,
    incident_type: str | None = None,
    status: str | None = None,
    sort_by: str = DEFAULT_INCIDENT_SORT_BY,
    sort_order: str = DEFAULT_INCIDENT_SORT_ORDER,
    user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return call_service(
        container.incident_service.list_incidents,
        user,
        q=q,
        incident_type=incident_type,
        status=status,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.post("/incidents")
def create_incident(
    payload: IncidentCreate,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.incident_service.create_incident,
        user,
        payload.model_dump(),
    )


@router.get("/incidents/dispatch-rules")
def list_dispatch_rules(
    _user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return call_service(container.dispatcher.list_rules_serialized)


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: int,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(container.incident_service.get_incident, user, incident_id)


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.incident_service.update_incident,
        user,
        incident_id,
        payload.model_dump(exclude_unset=True),
    )


@router.post("/incidents/{incident_id}/status")
def change_status(
    incident_id: int,
    payload: StatusTransition,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.incident_service.change_status,
        user,
        incident_id,
        payload.status,
        payload.outcome,
    )


@router.post("/signals")
def ingest_signal(payload: SignalIn) -> dict[str, Any]:
    return call_service(container.ingestion_service.receive, payload.model_dump())
