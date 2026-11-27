from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, BeforeValidator, field_validator, model_validator

from app.container import container
from app.enums import TaskStatus
from app.services.exceptions import ValidationError
from app.services.validators import (
    optional_iso_datetime,
    optional_text,
    require_iso_datetime,
    require_non_blank,
    require_positive_int,
)
from auth import get_current_user
from routers import call_service

router = APIRouter(prefix="/api", tags=["ops"])

NormalizedTaskStatus = Annotated[TaskStatus, BeforeValidator(TaskStatus.normalize)]


def _validate_positive_int_list(value: Any, field_name: str, *, allow_empty: bool) -> list[int]:
    """Validate a JSON list of positive non-bool integers."""
    if not isinstance(value, list):
        raise ValidationError(f"Поле '{field_name}' должно быть списком")
    if not allow_empty and not value:
        raise ValidationError(f"Поле '{field_name}' не может быть пустым")
    return [require_positive_int(item, field_name) for item in value]


class StepUpdate(BaseModel):
    completed: bool


class TaskCreate(BaseModel):
    title: str
    description: str = ""
    assigned_to: int | None = None
    assignee_ids: list[int] | None = None
    due_date: str | None = None

    @field_validator("title", mode="before")
    @classmethod
    def _validate_title(cls, value: Any) -> str:
        return require_non_blank(value, "title")

    @field_validator("description", mode="before")
    @classmethod
    def _validate_description(cls, value: Any) -> str:
        return optional_text(value, "description")

    @field_validator("assigned_to", mode="before")
    @classmethod
    def _validate_assigned_to(cls, value: Any) -> int | None:
        if value is None:
            return None
        return require_positive_int(value, "assigned_to")

    @field_validator("assignee_ids", mode="before")
    @classmethod
    def _validate_assignee_ids(cls, value: Any) -> list[int] | None:
        if value is None:
            return None
        return _validate_positive_int_list(value, "assignee_ids", allow_empty=False)

    @field_validator("due_date", mode="before")
    @classmethod
    def _validate_due_date(cls, value: Any) -> str | None:
        return optional_iso_datetime(value, "due_date")

    @model_validator(mode="after")
    def _validate_any_assignee(self) -> "TaskCreate":
        if self.assigned_to is None and not self.assignee_ids:
            raise ValidationError("Необходимо указать исполнителя (assigned_to или assignee_ids)")
        return self


class TaskUpdate(BaseModel):
    status: NormalizedTaskStatus | None = None
    result: str | None = None
    assigned_to: int | None = None
    assignee_ids: list[int] | None = None
    due_date: str | None = None

    @field_validator("assigned_to", mode="before")
    @classmethod
    def _validate_assigned_to(cls, value: Any) -> int | None:
        if value is None:
            return None
        return require_positive_int(value, "assigned_to")

    @field_validator("assignee_ids", mode="before")
    @classmethod
    def _validate_assignee_ids(cls, value: Any) -> list[int] | None:
        if value is None:
            return None
        return _validate_positive_int_list(value, "assignee_ids", allow_empty=True)

    @field_validator("due_date", mode="before")
    @classmethod
    def _validate_due_date(cls, value: Any) -> str | None:
        if value is None:
            return None
        return require_iso_datetime(value, "due_date")

    @model_validator(mode="after")
    def _validate_done_result(self) -> "TaskUpdate":
        if self.status is not None and TaskStatus.is_done(self.status):
            if self.result is not None and not self.result.strip():
                raise ValidationError("Для завершения задачи поле 'result' не может быть пустым")
        return self


class TaskAssigneesUpdate(BaseModel):
    assignee_ids: list[int]

    @field_validator("assignee_ids", mode="before")
    @classmethod
    def _validate_assignee_ids(cls, value: Any) -> list[int]:
        return _validate_positive_int_list(value, "assignee_ids", allow_empty=True)


class TaskAssigneeAdd(BaseModel):
    user_id: int

    @field_validator("user_id", mode="before")
    @classmethod
    def _validate_user_id(cls, value: Any) -> int:
        return require_positive_int(value, "user_id")


class RknDraftUpdate(BaseModel):
    rkn_draft: str


class RknConfirm(BaseModel):
    confirmation: str = ""


@router.get("/users")
def list_users(
    role: str | None = Query(default=None),
    assignable: bool = Query(default=False),
    _user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return call_service(
        container.user_service.list_users,
        role=role,
        assignable=assignable,
    )


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
        payload.model_dump(exclude_unset=True),
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


@router.put("/tasks/{task_id}/assignees")
def set_task_assignees(
    task_id: int,
    payload: TaskAssigneesUpdate,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.task_service.set_assignees,
        user,
        task_id,
        payload.assignee_ids,
    )


@router.post("/tasks/{task_id}/assignees")
def add_task_assignee(
    task_id: int,
    payload: TaskAssigneeAdd,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.task_service.add_assignee,
        user,
        task_id,
        payload.user_id,
    )


@router.delete("/tasks/{task_id}/assignees/{user_id}")
def remove_task_assignee(
    task_id: int,
    user_id: int,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.task_service.remove_assignee,
        user,
        task_id,
        user_id,
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


@router.post("/incidents/{incident_id}/rkn/confirm")
def confirm_rkn_sent(
    incident_id: int,
    payload: RknConfirm,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.deadline_service.mark_sent,
        user,
        incident_id,
        payload.confirmation,
    )


@router.post("/escalations/check")
def check_escalations(_user: dict[str, Any] = Depends(get_current_user)) -> list[dict[str, Any]]:
    return call_service(container.escalation_service.check_escalations)


@router.get("/notifications")
def list_notifications(
    recipient_role: str | None = Query(default=None),
    q: str | None = Query(default=None),
    kind: str | None = Query(default=None),
    incident_id: int | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    _user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return call_service(
        container.notification_service.list_notifications,
        recipient_role=recipient_role,
        q=q,
        kind=kind,
        incident_id=incident_id,
        date_from=date_from,
        date_to=date_to,
    )


@router.get("/reports/monthly")
def monthly_report(
    year: int | None = Query(default=None),
    month: int | None = Query(default=None, ge=1, le=12),
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(container.report_service.monthly_report, year=year, month=month)


@router.get("/reports/by-type")
def report_by_type(
    year: int | None = Query(default=None),
    month: int | None = Query(default=None, ge=1, le=12),
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(container.report_service.by_type_report, year=year, month=month)
