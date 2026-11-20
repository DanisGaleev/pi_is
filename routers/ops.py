from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, BeforeValidator, ValidationInfo, field_validator, model_validator

from app.container import container
from app.enums import TaskStatus
from app.services.exceptions import ValidationError
from app.services.validators import (
    require_iso_datetime,
    require_non_blank,
    require_positive_int,
)
from auth import get_current_user
from routers import call_service

router = APIRouter(prefix="/api", tags=["ops"])

NormalizedTaskStatus = Annotated[TaskStatus, BeforeValidator(TaskStatus.normalize)]


class StepUpdate(BaseModel):
    completed: bool


class TaskCreate(BaseModel):
    title: str
    description: str
    assigned_to: int
    due_date: str

    @field_validator("title", "description", mode="before")
    @classmethod
    def _validate_non_blank(cls, value: Any, info: ValidationInfo) -> str:
        return require_non_blank(value, info.field_name or "field")

    @field_validator("assigned_to", mode="before")
    @classmethod
    def _validate_assigned_to(cls, value: Any) -> int:
        return require_positive_int(value, "assigned_to")

    @field_validator("due_date", mode="before")
    @classmethod
    def _validate_due_date(cls, value: Any) -> str:
        return require_iso_datetime(value, "due_date")


class TaskUpdate(BaseModel):
    status: NormalizedTaskStatus | None = None
    result: str | None = None

    @model_validator(mode="after")
    def _validate_done_result(self) -> "TaskUpdate":
        if self.status is not None and TaskStatus.is_done(self.status):
            if self.result is not None and not self.result.strip():
                raise ValidationError("Для завершения задачи поле 'result' не может быть пустым")
        return self


class RknDraftUpdate(BaseModel):
    rkn_draft: str


@router.get("/instructions")
def list_instructions(_user: dict[str, Any] = Depends(get_current_user)) -> list[dict[str, Any]]:
    return call_service(container.instruction_service.list_instructions)


@router.put("/incidents/{incident_id}/steps/{step_index}")
def update_step_progress(
    incident_id: int,
    step_index: int,
    payload: StepUpdate,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.instruction_service.update_step,
        user,
        incident_id,
        step_index,
        payload.completed,
    )


@router.post("/incidents/{incident_id}/tasks")
def create_task(
    incident_id: int,
    payload: TaskCreate,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.task_service.create_task,
        user,
        incident_id,
        payload.model_dump(),
    )


@router.get("/tasks")
def list_tasks(
    assigned_to: str | None = Query(default=None),
    status: str | None = Query(default=None),
    incident_id: int | None = Query(default=None),
    user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return call_service(
        container.task_service.list_tasks,
        user,
        assigned_to=assigned_to,
        status=status,
        incident_id=incident_id,
    )


@router.patch("/tasks/{task_id}")
def update_task(
    task_id: int,
    payload: TaskUpdate,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.task_service.update_task,
        user,
        task_id,
        payload.model_dump(exclude_unset=True),
    )


@router.get("/incidents/{incident_id}/rkn")
def get_rkn_info(
    incident_id: int,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(container.deadline_service.get_notice, user, incident_id)


@router.put("/incidents/{incident_id}/rkn")
def update_rkn_draft(
    incident_id: int,
    payload: RknDraftUpdate,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.deadline_service.update_draft,
        user,
        incident_id,
        payload.rkn_draft,
    )


@router.post("/escalations/check")
def check_escalations(_user: dict[str, Any] = Depends(get_current_user)) -> list[dict[str, Any]]:
    return call_service(container.escalation_service.check_escalations)


@router.get("/notifications")
def list_notifications(
    recipient_role: str | None = Query(default=None),
    _user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return call_service(
        container.notification_service.list_notifications,
        recipient_role=recipient_role,
    )


@router.get("/reports/monthly")
def monthly_report(
    year: int | None = Query(default=None),
    month: int | None = Query(default=None, ge=1, le=12),
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(container.report_service.monthly_report, year=year, month=month)
