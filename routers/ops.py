from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, BeforeValidator

from app.container import container
from app.enums import TaskStatus
from auth import get_current_user
from routers import call_service

router = APIRouter(prefix="/api", tags=["ops"])

NormalizedTaskStatus = Annotated[TaskStatus, BeforeValidator(TaskStatus.normalize)]


class StepUpdate(BaseModel):
    completed: bool


class TaskCreate(BaseModel):
    title: str
    description: str = ""
    assigned_to: int | None = None


class TaskUpdate(BaseModel):
    status: NormalizedTaskStatus | None = None
    result: str | None = None
    assigned_to: int | None = None


class RknDraftUpdate(BaseModel):
    rkn_draft: str


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
