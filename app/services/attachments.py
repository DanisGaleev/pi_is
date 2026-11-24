import os
import uuid
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from app.domain.models import Attachment, User
from app.repositories.sqlite_repo import (
    AttachmentRepository,
    HistoryRepository,
    IncidentRepository,
    TaskRepository,
    UserRepository,
    utc_now,
)
from app.services.access import AccessControlService
from app.services.exceptions import NotFoundError, ValidationError, coerce_user

MAX_ATTACHMENT_SIZE_BYTES = 10 * 1024 * 1024  # 10 MiB

IMAGE_EXTENSIONS: dict[str, str] = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".bmp": "image/bmp",
}

TEXT_EXTENSIONS: dict[str, str] = {
    ".txt": "text/plain",
    ".log": "text/plain",
    ".md": "text/markdown",
    ".json": "application/json",
    ".xml": "application/xml",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
    ".ini": "text/plain",
    ".conf": "text/plain",
}

TABLE_EXTENSIONS: dict[str, str] = {
    ".csv": "text/csv",
    ".tsv": "text/tab-separated-values",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xls": "application/vnd.ms-excel",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
}

ALLOWED_EXTENSION_MIMES: dict[str, str] = {
    **IMAGE_EXTENSIONS,
    **TEXT_EXTENSIONS,
    **TABLE_EXTENSIONS,
}

_CATEGORY_ALLOWED_MIMES: dict[str, frozenset[str]] = {
    "image": frozenset(IMAGE_EXTENSIONS.values()),
    "text": frozenset(
        {
            "text/plain",
            "text/markdown",
            "text/x-markdown",
            "text/json",
            "application/json",
            "text/xml",
            "application/xml",
            "text/yaml",
            "text/x-yaml",
            "application/yaml",
            "application/x-yaml",
        }
    ),
    "table": frozenset(
        {
            "text/csv",
            "application/csv",
            "text/tab-separated-values",
            "text/plain",
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.oasis.opendocument.spreadsheet",
        }
    ),
}

_GENERIC_UPLOAD_MIMES: frozenset[str] = frozenset(
    {
        "",
        "application/octet-stream",
        "binary/octet-stream",
    }
)


def classify_extension(ext: str) -> str:
    """Classify an allowed file extension into image, text, or table."""
    lowered = ext.lower()
    if lowered in IMAGE_EXTENSIONS:
        return "image"
    if lowered in TEXT_EXTENSIONS:
        return "text"
    if lowered in TABLE_EXTENSIONS:
        return "table"
    return "other"


def serialize_attachment(
    attachment: Attachment,
    users_by_id: Mapping[int, User] | None = None,
) -> dict[str, Any]:
    """Serialize an Attachment with download URL, category, and uploader summary."""
    data = attachment.to_dict()
    ext = Path(attachment.filename).suffix.lower()
    data["file_category"] = classify_extension(ext)
    data["download_url"] = f"/api/attachments/{attachment.id}/download"
    if users_by_id is not None:
        uploader = (
            users_by_id.get(int(attachment.uploaded_by))
            if attachment.uploaded_by is not None
            else None
        )
        data["uploaded_by_user"] = uploader.to_summary_dict() if uploader is not None else None
    return data


def enrich_attachments_with_users(
    attachments: Iterable[Attachment],
    user_repo: UserRepository | None,
) -> list[dict[str, Any]]:
    """Serialize attachments and attach uploaded_by_user summaries."""
    items = list(attachments)
    if not items:
        return []
    user_ids = {int(att.uploaded_by) for att in items if att.uploaded_by is not None}
    users_by_id = (
        user_repo.get_by_ids(user_ids)
        if (user_repo is not None and user_ids)
        else {}
    )
    return [serialize_attachment(att, users_by_id) for att in items]


def enrich_tasks_with_attachments(
    task_dicts: list[dict[str, Any]],
    attachment_repo: AttachmentRepository | None,
    user_repo: UserRepository | None = None,
) -> list[dict[str, Any]]:
    """Attach serialized attachments list to each task dictionary."""
    if not task_dicts:
        return task_dicts
    if attachment_repo is None:
        for item in task_dicts:
            item.setdefault("attachments", [])
        return task_dicts

    task_ids = [int(item["id"]) for item in task_dicts if item.get("id") is not None]
    by_task = attachment_repo.list_by_task_ids(task_ids)
    uploader_ids = {
        int(att.uploaded_by)
        for atts in by_task.values()
        for att in atts
        if att.uploaded_by is not None
    }
    users_by_id = (
        user_repo.get_by_ids(uploader_ids)
        if (user_repo is not None and uploader_ids)
        else {}
    )
    for item in task_dicts:
        tid = item.get("id")
        atts = by_task.get(int(tid), []) if tid is not None else []
        item["attachments"] = [serialize_attachment(att, users_by_id) for att in atts]
    return task_dicts


class AttachmentService:
    """File upload, storage, task attachment management, and download service."""

    def __init__(
        self,
        attachment_repo: AttachmentRepository,
        incident_repo: IncidentRepository,
        task_repo: TaskRepository,
        history_repo: HistoryRepository,
        access_control: AccessControlService,
        user_repo: UserRepository | None = None,
        upload_dir: str | Path | None = None,
    ) -> None:
        self.attachment_repo = attachment_repo
        self.incident_repo = incident_repo
        self.task_repo = task_repo
        self.history_repo = history_repo
        self.access_control = access_control
        self.user_repo = user_repo
        self._upload_dir = Path(upload_dir) if upload_dir is not None else None

    def resolve_upload_dir(self) -> Path:
        """Resolve the active file storage directory (UPLOAD_DIR, explicit path, or beside DB)."""
        env_dir = os.environ.get("UPLOAD_DIR")
        if env_dir and env_dir.strip():
            return Path(env_dir.strip())
        if self._upload_dir is not None:
            return self._upload_dir
        db_path = self.attachment_repo.db.resolve_path()
        if db_path == ":memory:" or db_path.startswith("file:"):
            return Path("uploads")
        return Path(db_path).resolve().parent / "uploads"

    def _validate_and_normalize_file(
        self,
        filename: str | None,
        content: bytes,
        content_type: str | None,
    ) -> tuple[str, str, str]:
        """Validate filename, extension, MIME type, and size; return (safe_name, ext, mime)."""
        raw_name = (filename or "").strip()
        if not raw_name or ".." in raw_name.replace("\\", "/").split("/"):
            raise ValidationError("Некорректное имя файла")

        safe_name = Path(raw_name.replace("\\", "/")).name.strip()
        if not safe_name or safe_name in {".", ".."}:
            raise ValidationError("Некорректное имя файла")

        ext = Path(safe_name).suffix.lower()
        if ext not in ALLOWED_EXTENSION_MIMES:
            allowed = ", ".join(sorted(ALLOWED_EXTENSION_MIMES))
            raise ValidationError(
                f"Недопустимый тип файла '{ext or '(без расширения)'}'. "
                f"Разрешены изображения, текстовые файлы и таблицы: {allowed}"
            )

        if not isinstance(content, (bytes, bytearray)) or len(content) == 0:
            raise ValidationError("Загружаемый файл не может быть пустым")
        if len(content) > MAX_ATTACHMENT_SIZE_BYTES:
            limit_mb = MAX_ATTACHMENT_SIZE_BYTES // (1024 * 1024)
            raise ValidationError(f"Размер файла превышает допустимый лимит ({limit_mb} МБ)")

        normalized_ct = (content_type or "").split(";", 1)[0].strip().lower()
        category = classify_extension(ext)
        default_mime = ALLOWED_EXTENSION_MIMES[ext]

        if normalized_ct in _GENERIC_UPLOAD_MIMES:
            return safe_name, ext, default_mime

        allowed_mimes = _CATEGORY_ALLOWED_MIMES.get(category, frozenset())
        if normalized_ct not in allowed_mimes and not (
            category == "image" and normalized_ct.startswith("image/")
        ) and not (
            category == "text" and normalized_ct.startswith("text/")
        ):
            raise ValidationError(
                f"MIME-тип '{normalized_ct}' не соответствует расширению файла '{ext}'"
            )

        return safe_name, ext, normalized_ct

    def _save_to_disk(self, incident_id: int, ext: str, content: bytes) -> tuple[str, Path]:
        """Persist uploaded bytes inside incident subfolder and return (relative_key, abs_path)."""
        root = self.resolve_upload_dir().resolve()
        subdir = root / f"incident_{incident_id}"
        subdir.mkdir(parents=True, exist_ok=True)
        stored_name = f"{uuid.uuid4().hex}{ext}"
        abs_path = (subdir / stored_name).resolve()
        abs_path.write_bytes(content)
        rel_key = f"incident_{incident_id}/{stored_name}"
        return rel_key, abs_path

    def _resolve_stored_path(self, attachment: Attachment) -> Path:
        """Resolve an attachment's disk path safely inside the upload root."""
        stored = Path(attachment.path)
        if stored.is_absolute():
            return stored
        root = self.resolve_upload_dir().resolve()
        resolved = (root / stored).resolve()
        if resolved != root and root not in resolved.parents:
            raise ValidationError("Недопустимый путь к файлу вложения")
        return resolved

    def _serialize_one(self, attachment: Attachment) -> dict[str, Any]:
        return enrich_attachments_with_users([attachment], self.user_repo)[0]

    def list_incident_attachments(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
        task_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """List attachments on an incident (optionally filtered by task_id) after RBAC check."""
        actor = coerce_user(user)
        if task_id is not None:
            self.access_control.assert_task_view_access(actor)
        incident = self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_access(actor, incident, edit=False)
        items = self.attachment_repo.list_by_incident(incident_id, task_id=task_id)
        return enrich_attachments_with_users(items, self.user_repo)

    def list_task_attachments(
        self,
        user: User | Mapping[str, Any],
        task_id: int,
    ) -> list[dict[str, Any]]:
        """List attachments linked to a task after task/incident RBAC checks."""
        actor = coerce_user(user)
        self.access_control.assert_task_view_access(actor)
        task = self.task_repo.get_by_id(task_id)
        if task is None:
            raise NotFoundError("Задача не найдена")
        incident = self.incident_repo.get_by_id(task.incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_access(actor, incident, edit=False)
        items = self.attachment_repo.list_by_task(task_id)
        return enrich_attachments_with_users(items, self.user_repo)

    def get_attachment(
        self,
        user: User | Mapping[str, Any],
        attachment_id: int,
    ) -> dict[str, Any]:
        """Return metadata for a single attachment after verifying access."""
        actor = coerce_user(user)
        attachment = self.attachment_repo.get_by_id(attachment_id)
        if attachment is None:
            raise NotFoundError("Вложение не найдено")
        incident = self.incident_repo.get_by_id(attachment.incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_access(actor, incident, edit=False)
        return self._serialize_one(attachment)

    def get_attachment_download(
        self,
        user: User | Mapping[str, Any],
        attachment_id: int,
    ) -> tuple[Attachment, Path]:
        """Authorize download and return the Attachment model and verified disk path."""
        actor = coerce_user(user)
        attachment = self.attachment_repo.get_by_id(attachment_id)
        if attachment is None:
            raise NotFoundError("Вложение не найдено")
        incident = self.incident_repo.get_by_id(attachment.incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_access(actor, incident, edit=False)

        file_path = self._resolve_stored_path(attachment)
        if not file_path.is_file():
            raise NotFoundError("Файл вложения не найден на диске")
        self.access_control.log_access(actor.id, "attachment", attachment.id, "download")
        return attachment, file_path

    def upload_to_incident(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
        filename: str | None,
        content: bytes,
        content_type: str | None = None,
        task_id: int | None = None,
    ) -> dict[str, Any]:
        """Upload a validated file to an incident (and optionally link it to a task)."""
        actor = coerce_user(user)
        incident = self.incident_repo.get_by_id(incident_id)
        self.access_control.assert_operational_incident_access(
            actor,
            incident,
            object_type="attachment",
            object_id=None,
            action="upload_denied",
            detail="Загрузка файлов к инциденту запрещена",
        )
        if incident is None:
            raise NotFoundError("Инцидент не найден")

        if task_id is not None:
            task = self.task_repo.get_by_id(task_id)
            if task is None:
                raise NotFoundError("Задача не найдена")
            if task.incident_id != incident_id:
                raise ValidationError("Указанная задача принадлежит другому инциденту")

        safe_name, ext, mime_type = self._validate_and_normalize_file(
            filename, content, content_type
        )
        rel_key, abs_path = self._save_to_disk(incident_id, ext, content)
        now = utc_now()
        try:
            created = self.attachment_repo.create(
                incident_id=incident_id,
                task_id=task_id,
                filename=safe_name,
                mime_type=mime_type,
                path=rel_key,
                size_bytes=len(content),
                uploaded_by=actor.id,
                uploaded_at=now,
            )
        except Exception:
            abs_path.unlink(missing_ok=True)
            raise

        self.incident_repo.touch_updated_at(incident_id, now)
        details = (
            f"Загружен файл «{safe_name}» к задаче #{task_id}"
            if task_id is not None
            else f"Загружен файл «{safe_name}»"
        )
        self.history_repo.add(
            incident_id=incident_id,
            user_id=actor.id,
            action="attachment_uploaded",
            details=details,
            created_at=now,
        )
        self.access_control.log_access(actor.id, "attachment", created.id, "upload")
        return self._serialize_one(created)

    def upload_to_task(
        self,
        user: User | Mapping[str, Any],
        task_id: int,
        filename: str | None,
        content: bytes,
        content_type: str | None = None,
    ) -> dict[str, Any]:
        """Upload a file directly to a task (and its parent incident)."""
        actor = coerce_user(user)
        self.access_control.assert_operational_access(
            actor,
            "task",
            task_id,
            action="upload_denied",
            detail="Загрузка файлов к задаче запрещена",
        )
        task = self.task_repo.get_by_id(task_id)
        if task is None:
            raise NotFoundError("Задача не найдена")
        return self.upload_to_incident(
            actor,
            task.incident_id,
            filename,
            content,
            content_type=content_type,
            task_id=task.id,
        )

    def attach_to_task(
        self,
        user: User | Mapping[str, Any],
        task_id: int,
        attachment_id: int,
    ) -> dict[str, Any]:
        """Link an existing incident attachment to a task of the same incident."""
        actor = coerce_user(user)
        self.access_control.assert_operational_access(
            actor,
            "task",
            task_id,
            action="edit_denied",
            detail="Управление файлами задачи запрещено",
        )
        task = self.task_repo.get_by_id(task_id)
        if task is None:
            raise NotFoundError("Задача не найдена")
        incident = self.incident_repo.get_by_id(task.incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_access(actor, incident, edit=True)

        attachment = self.attachment_repo.get_by_id(attachment_id)
        if attachment is None:
            raise NotFoundError("Вложение не найдено")
        if attachment.incident_id != task.incident_id:
            raise ValidationError("Нельзя привязать файл другого инцидента к задаче")

        updated = self.attachment_repo.update_task_id(attachment_id, task.id)
        assert updated is not None
        now = utc_now()
        self.incident_repo.touch_updated_at(task.incident_id, now)
        self.history_repo.add(
            incident_id=task.incident_id,
            user_id=actor.id,
            action="attachment_linked",
            details=f"Файл «{updated.filename}» (#{updated.id}) привязан к задаче #{task.id}",
            created_at=now,
        )
        self.access_control.log_access(actor.id, "attachment", updated.id, "link_task")
        return self._serialize_one(updated)

    def detach_from_task(
        self,
        user: User | Mapping[str, Any],
        task_id: int,
        attachment_id: int,
        *,
        delete_file: bool = False,
    ) -> dict[str, Any]:
        """Detach an attachment from a task (keeping it on the incident) or delete it."""
        actor = coerce_user(user)
        self.access_control.assert_operational_access(
            actor,
            "task",
            task_id,
            action="edit_denied",
            detail="Управление файлами задачи запрещено",
        )
        task = self.task_repo.get_by_id(task_id)
        if task is None:
            raise NotFoundError("Задача не найдена")
        incident = self.incident_repo.get_by_id(task.incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_access(actor, incident, edit=True)

        attachment = self.attachment_repo.get_by_id(attachment_id)
        if attachment is None or attachment.task_id != task.id:
            raise NotFoundError("Файл задачи не найден")

        if delete_file:
            deleted_info = self.delete_attachment(actor, attachment_id)
            return {"detached": True, **deleted_info}

        updated = self.attachment_repo.update_task_id(attachment_id, None)
        assert updated is not None
        now = utc_now()
        self.incident_repo.touch_updated_at(task.incident_id, now)
        self.history_repo.add(
            incident_id=task.incident_id,
            user_id=actor.id,
            action="attachment_detached",
            details=f"Файл «{updated.filename}» (#{updated.id}) убран из задачи #{task.id}",
            created_at=now,
        )
        self.access_control.log_access(actor.id, "attachment", updated.id, "detach_task")
        return {
            "detached": True,
            "deleted": False,
            "attachment": self._serialize_one(updated),
        }

    def delete_attachment(
        self,
        user: User | Mapping[str, Any],
        attachment_id: int,
        *,
        incident_id: int | None = None,
    ) -> dict[str, Any]:
        """Permanently delete an attachment record from DB and remove the file from disk."""
        actor = coerce_user(user)
        self.access_control.assert_operational_access(
            actor,
            "attachment",
            attachment_id,
            action="delete_denied",
            detail="Удаление файлов запрещено",
        )
        attachment = self.attachment_repo.get_by_id(attachment_id)
        if attachment is None:
            raise NotFoundError("Вложение не найдено")
        if incident_id is not None and attachment.incident_id != incident_id:
            raise NotFoundError("Вложение инцидента не найдено")

        incident = self.incident_repo.get_by_id(attachment.incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_access(actor, incident, edit=True)

        file_path = self._resolve_stored_path(attachment)
        deleted = self.attachment_repo.delete(attachment_id)
        if deleted is None:
            raise NotFoundError("Вложение не найдено")
        file_path.unlink(missing_ok=True)

        now = utc_now()
        self.incident_repo.touch_updated_at(attachment.incident_id, now)
        self.history_repo.add(
            incident_id=attachment.incident_id,
            user_id=actor.id,
            action="attachment_deleted",
            details=f"Удалён файл «{deleted.filename}» (#{deleted.id})",
            created_at=now,
        )
        self.access_control.log_access(actor.id, "attachment", deleted.id, "delete")
        return {
            "deleted": True,
            "attachment_id": deleted.id,
            "incident_id": deleted.incident_id,
            "task_id": deleted.task_id,
        }
