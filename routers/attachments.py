from typing import Any

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import FileResponse

from app.container import container
from auth import get_current_user
from routers import call_service

router = APIRouter(prefix="/api", tags=["attachments"])


@router.get("/incidents/{incident_id}/attachments")
def list_incident_attachments(
    incident_id: int,
    task_id: int | None = Query(default=None),
    user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return call_service(
        container.attachment_service.list_incident_attachments,
        user,
        incident_id,
        task_id=task_id,
    )


@router.post("/incidents/{incident_id}/attachments")
async def upload_incident_attachment(
    incident_id: int,
    file: UploadFile = File(...),
    task_id: int | None = Form(default=None),
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    content = await file.read()
    return call_service(
        container.attachment_service.upload_to_incident,
        user,
        incident_id,
        file.filename,
        content,
        content_type=file.content_type,
        task_id=task_id,
    )


@router.delete("/incidents/{incident_id}/attachments/{attachment_id}")
def delete_incident_attachment(
    incident_id: int,
    attachment_id: int,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.attachment_service.delete_attachment,
        user,
        attachment_id,
        incident_id=incident_id,
    )


@router.get("/tasks/{task_id}/attachments")
def list_task_attachments(
    task_id: int,
    user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return call_service(
        container.attachment_service.list_task_attachments,
        user,
        task_id,
    )


@router.post("/tasks/{task_id}/attachments")
async def upload_task_attachment(
    task_id: int,
    file: UploadFile = File(...),
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    content = await file.read()
    return call_service(
        container.attachment_service.upload_to_task,
        user,
        task_id,
        file.filename,
        content,
        content_type=file.content_type,
    )


@router.post("/tasks/{task_id}/attachments/{attachment_id}")
def attach_existing_file_to_task(
    task_id: int,
    attachment_id: int,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.attachment_service.attach_to_task,
        user,
        task_id,
        attachment_id,
    )


@router.delete("/tasks/{task_id}/attachments/{attachment_id}")
def detach_or_delete_task_attachment(
    task_id: int,
    attachment_id: int,
    delete_file: bool = Query(default=False),
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.attachment_service.detach_from_task,
        user,
        task_id,
        attachment_id,
        delete_file=delete_file,
    )


@router.get("/attachments/{attachment_id}")
def get_attachment(
    attachment_id: int,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.attachment_service.get_attachment,
        user,
        attachment_id,
    )


@router.get("/attachments/{attachment_id}/download")
def download_attachment(
    attachment_id: int,
    user: dict[str, Any] = Depends(get_current_user),
) -> FileResponse:
    attachment, file_path = call_service(
        container.attachment_service.get_attachment_download,
        user,
        attachment_id,
    )
    return FileResponse(
        path=file_path,
        media_type=attachment.mime_type,
        filename=attachment.filename,
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.delete("/attachments/{attachment_id}")
def delete_attachment(
    attachment_id: int,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.attachment_service.delete_attachment,
        user,
        attachment_id,
    )
