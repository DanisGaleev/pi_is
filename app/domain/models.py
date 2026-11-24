from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.enums import (
    AccessCategory,
    Channel,
    DeliveryStatus,
    IncidentStatus,
    IncidentType,
    PdnFlag,
    ReportFormat,
    Role,
    Severity,
    SourceType,
    TaskStatus,
)


def _parse_iso_utc(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp string, defaulting naive values to UTC."""
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass
class User:
    """System user participating in incident response."""

    id: int
    username: str
    full_name: str
    role: Role
    active: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.role, str) and not isinstance(self.role, Role):
            try:
                self.role = Role(self.role)
            except ValueError:
                pass
        self.active = bool(self.active)

    @property
    def role_label(self) -> str:
        """Return the Russian display label for the user's role."""
        try:
            return Role(self.role).label
        except ValueError:
            return str(self.role)

    @property
    def display_label(self) -> str:
        """Return formatted picker label '<full_name> — <role_label>'."""
        return f"{self.full_name} — {self.role_label}"

    def to_summary_dict(self) -> dict[str, Any]:
        """Serialize user summary fields including role label and picker label."""
        role_val = self.role.value if isinstance(self.role, Role) else str(self.role)
        role_lbl = self.role_label
        return {
            "id": self.id,
            "username": self.username,
            "full_name": self.full_name,
            "role": role_val,
            "role_label": role_lbl,
            "label": f"{self.full_name} — {role_lbl}",
        }

    def to_picker_dict(self) -> dict[str, Any]:
        """Serialize user fields including active status for assignee selection."""
        data = self.to_summary_dict()
        data["active"] = self.active
        return data

    def to_dict(self) -> dict[str, Any]:
        """Serialize user fields to a plain dictionary."""
        return {
            "id": self.id,
            "username": self.username,
            "full_name": self.full_name,
            "role": self.role,
            "active": self.active,
        }


@dataclass
class Computer:
    """Managed workstation or server asset."""

    hostname: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize computer fields to a plain dictionary."""
        return {"hostname": self.hostname}


@dataclass
class Department:
    """Organizational unit."""

    name: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize department fields to a plain dictionary."""
        return {"name": self.name}


@dataclass
class Site:
    """Physical office or construction site."""

    name: str
    address: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize site fields to a plain dictionary."""
        return {"name": self.name, "address": self.address}


@dataclass
class IncomingMessage:
    """Raw signal or message attached to an incident."""

    id: int
    incident_id: int
    source: str
    sender: str
    body: str
    incident_key: str
    received_at: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize message fields to a plain dictionary."""
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "source": self.source,
            "sender": self.sender,
            "body": self.body,
            "incident_key": self.incident_key,
            "received_at": self.received_at,
        }


@dataclass
class HistoryRecord:
    """Immutable audit timeline entry for an incident."""

    id: int
    incident_id: int
    user_id: int | None
    action: str
    details: str
    created_at: str
    username: str | None = None
    full_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize history record fields to a plain dictionary."""
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "user_id": self.user_id,
            "action": self.action,
            "details": self.details,
            "created_at": self.created_at,
            "username": self.username,
            "full_name": self.full_name,
        }


@dataclass
class InstructionVersion:
    """Versioned snapshot of instruction checklist steps."""

    version: int
    steps: list[str]
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize instruction version to a plain dictionary."""
        return {
            "version": self.version,
            "steps": list(self.steps),
            "created_at": self.created_at,
        }


@dataclass
class Instruction:
    """Response playbook template mapped to an incident category."""

    id: int
    title: str
    incident_type: str
    steps: list[str]
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Serialize instruction fields to a plain dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "incident_type": self.incident_type,
            "steps": list(self.steps),
            "version": self.version,
        }


@dataclass
class InstructionProgress:
    """Completion state of a single playbook step for an incident."""

    incident_id: int
    step_index: int
    completed: bool
    updated_by: int | None
    updated_at: str

    def __post_init__(self) -> None:
        self.completed = bool(self.completed)

    def to_dict(self) -> dict[str, Any]:
        """Serialize step progress fields to a plain dictionary."""
        return {
            "incident_id": self.incident_id,
            "step_index": self.step_index,
            "completed": self.completed,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at,
        }


MAX_TASK_ASSIGNEES = 3


def _normalize_assignee_ids(user_ids: Iterable[int]) -> list[int]:
    """Deduplicate task assignee IDs preserving order and validate limit."""
    unique: list[int] = []
    seen: set[int] = set()
    for uid in user_ids:
        uid_int = int(uid)
        if uid_int not in seen:
            seen.add(uid_int)
            unique.append(uid_int)
    if len(unique) > MAX_TASK_ASSIGNEES:
        raise ValueError(f"На задачу можно назначить не более {MAX_TASK_ASSIGNEES} исполнителей")
    return unique


@dataclass
class Task:
    """Remediation or investigation task assigned under an incident."""

    id: int
    incident_id: int
    title: str
    description: str
    assigned_to: int | None
    status: str
    result: str
    created_by: int | None
    created_at: str
    completed_at: str | None = None
    due_date: str | None = None
    assignee_ids: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.assignee_ids:
            self.assignee_ids = _normalize_assignee_ids(self.assignee_ids)
            self.assigned_to = self.assignee_ids[0]
        elif self.assigned_to is not None:
            self.assigned_to = int(self.assigned_to)
            self.assignee_ids = [self.assigned_to]
        else:
            self.assignee_ids = []

    def set_assignees(self, user_ids: Iterable[int]) -> None:
        """Replace task assignees (up to MAX_TASK_ASSIGNEES) and sync primary assigned_to."""
        self.assignee_ids = _normalize_assignee_ids(user_ids)
        self.assigned_to = self.assignee_ids[0] if self.assignee_ids else None

    def add_assignee(self, user_id: int) -> bool:
        """Add an assignee if absent and below MAX_TASK_ASSIGNEES; return True if added."""
        uid = int(user_id)
        if uid in self.assignee_ids:
            return False
        if len(self.assignee_ids) >= MAX_TASK_ASSIGNEES:
            raise ValueError(
                f"На задачу можно назначить не более {MAX_TASK_ASSIGNEES} исполнителей"
            )
        self.assignee_ids = [*self.assignee_ids, uid]
        self.assigned_to = self.assignee_ids[0]
        return True

    def remove_assignee(self, user_id: int) -> bool:
        """Remove an assignee if present and sync primary assigned_to; return True if removed."""
        uid = int(user_id)
        if uid not in self.assignee_ids:
            return False
        self.assignee_ids = [existing for existing in self.assignee_ids if existing != uid]
        self.assigned_to = self.assignee_ids[0] if self.assignee_ids else None
        return True

    def complete(self, result: str, completed_at: str) -> None:
        """Mark the task as completed with an outcome summary."""
        self.status = TaskStatus.DONE.value
        self.result = result
        self.completed_at = completed_at

    def is_overdue(self, now: datetime | None = None) -> bool:
        """Return True if the task is open past its due date or marked overdue."""
        if TaskStatus.is_done(self.status):
            return False
        if self.due_date:
            current = now or datetime.now(timezone.utc)
            if current.tzinfo is None:
                current = current.replace(tzinfo=timezone.utc)
            return current > _parse_iso_utc(self.due_date)
        return str(self.status).strip() == TaskStatus.OVERDUE.value

    def to_dict(self) -> dict[str, Any]:
        """Serialize task fields to a plain dictionary."""
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "assigned_to": self.assigned_to,
            "assignee_ids": list(self.assignee_ids),
            "status": self.status,
            "result": self.result,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "due_date": self.due_date,
        }


@dataclass
class FollowUpMeasure:
    """Post-incident preventive or corrective measure."""

    id: int
    incident_id: int
    cause: str
    action: str
    responsible_id: int | None
    due_date: str | None
    status: str
    result: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize follow-up measure fields to a plain dictionary."""
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "cause": self.cause,
            "action": self.action,
            "responsible_id": self.responsible_id,
            "due_date": self.due_date,
            "status": self.status,
            "result": self.result,
        }


@dataclass
class Attachment:
    """Evidence or document file attached to an incident."""

    id: int
    incident_id: int
    filename: str
    mime_type: str
    path: str
    uploaded_by: int | None
    uploaded_at: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize attachment metadata to a plain dictionary."""
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "filename": self.filename,
            "mime_type": self.mime_type,
            "path": self.path,
            "uploaded_by": self.uploaded_by,
            "uploaded_at": self.uploaded_at,
        }


@dataclass
class Deadlines:
    """Calculated Roskomnadzor 24h and 72h reporting deadlines."""

    detected_at: str
    deadline_24h: str
    deadline_72h: str
    overdue_24h: bool
    overdue_72h: bool

    def to_dict(self) -> dict[str, Any]:
        """Serialize deadline fields to a plain dictionary."""
        return {
            "detected_at": self.detected_at,
            "deadline_24h": self.deadline_24h,
            "deadline_72h": self.deadline_72h,
            "overdue_24h": self.overdue_24h,
            "overdue_72h": self.overdue_72h,
        }


@dataclass
class Incident:
    """Core cybersecurity incident aggregate."""

    id: int | None = None
    title: str = ""
    description: str = ""
    incident_type: str = IncidentType.OTHER.value
    severity: str = Severity.MEDIUM.value
    status: str = IncidentStatus.NEW.value
    outcome: str = ""
    computer: str = ""
    employee: str = ""
    source: str = SourceType.MANUAL.value
    incident_key: str = ""
    has_personal_data: int = 0
    instruction_id: int | None = None
    rkn_draft: str = ""
    detected_at: str = ""
    taken_at: str | None = None
    closed_at: str | None = None
    created_at: str = ""
    updated_at: str = ""
    access_category: str = ""
    assigned_to: int | None = None
    rkn_sent_at: str | None = None
    rkn_confirmation: str = ""

    def __post_init__(self) -> None:
        self.has_personal_data = PdnFlag.from_bool_int(self.has_personal_data).to_bool_int()
        if not self.access_category:
            self.access_category = self.resolve_access_category().value

    def resolve_access_category(self) -> AccessCategory:
        """Compute the access category from personal-data and employee attributes."""
        if PdnFlag.from_bool_int(self.has_personal_data) is PdnFlag.YES:
            return AccessCategory.PERSONAL_DATA
        if str(self.employee or "").strip():
            return AccessCategory.EMPLOYEE_INVOLVED
        return AccessCategory.TECHNICAL

    def refresh_access_category(self) -> AccessCategory:
        """Recompute and store access_category on the incident."""
        category = self.resolve_access_category()
        self.access_category = category.value
        return category

    def take(self, user_id: int | None, now: str) -> None:
        """Accept the incident into active work and optionally assign it."""
        self.status = IncidentStatus.IN_PROGRESS.value
        if not self.taken_at:
            self.taken_at = now
        if user_id is not None:
            self.assigned_to = user_id
        self.updated_at = now

    def assign(self, user_id: int | None, now: str | None = None) -> None:
        """Assign the incident to a responsible user."""
        self.assigned_to = user_id
        if now is not None:
            self.updated_at = now

    def send_to_review(self, now: str) -> None:
        """Move the incident to verification review."""
        self.status = IncidentStatus.IN_REVIEW.value
        self.updated_at = now

    def return_to_work(self, reason: str, now: str) -> None:
        """Return the incident from review or closure back to active work."""
        _ = reason
        self.status = IncidentStatus.IN_PROGRESS.value
        if not self.taken_at:
            self.taken_at = now
        self.closed_at = None
        self.updated_at = now

    def close(self, result: str, now: str) -> None:
        """Close the incident with a resolution outcome."""
        self.status = IncidentStatus.CLOSED.value
        if result is not None:
            self.outcome = str(result)
        self.closed_at = now
        self.updated_at = now

    def to_dict(self) -> dict[str, Any]:
        """Serialize incident fields to a plain dictionary matching DB columns."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "status": self.status,
            "outcome": self.outcome,
            "computer": self.computer,
            "employee": self.employee,
            "source": self.source,
            "incident_key": self.incident_key,
            "has_personal_data": self.has_personal_data,
            "instruction_id": self.instruction_id,
            "rkn_draft": self.rkn_draft,
            "detected_at": self.detected_at,
            "taken_at": self.taken_at,
            "closed_at": self.closed_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "access_category": self.access_category,
            "assigned_to": self.assigned_to,
            "rkn_sent_at": self.rkn_sent_at,
            "rkn_confirmation": self.rkn_confirmation,
        }


@dataclass
class RegulatorNotice:
    """Regulatory notification state and draft text for Roskomnadzor."""

    incident_id: int
    detected_at: str
    deadline_24h: str
    deadline_72h: str
    overdue_24h: bool
    overdue_72h: bool
    rkn_draft: str
    is_auto_generated: bool
    sent_at: str | None = None
    confirmation: str = ""

    @staticmethod
    def build_draft(incident: Incident, deadline_24h: str, deadline_72h: str) -> str:
        """Generate the default Russian regulatory notice text for an incident."""
        pdn_flag = (
            "Да" if PdnFlag.from_bool_int(incident.has_personal_data) is PdnFlag.YES else "Нет"
        )
        return (
            f"УВЕДОМЛЕНИЕ В РОСКОМНАДЗОР (первичное / 24 часа)\n"
            f"Инцидент #{incident.id}: {incident.title}\n"
            f"Тип инцидента: {incident.incident_type}\n"
            f"Дата и время выявления: {incident.detected_at}\n"
            f"Крайний срок первичного уведомления (24ч): {deadline_24h}\n"
            f"Крайний срок дополнительного уведомления (72ч): {deadline_72h}\n"
            f"Наличие ПДн: {pdn_flag}\n"
            f"Затронутый узел / сотрудник: {incident.computer or '-'} / {incident.employee or '-'}\n"
            f"Описание: {incident.description or '-'}\n"
            f"Принимаемые меры: проводится локализация и расследование инцидента ИБ."
        )

    def mark_sent(self, confirmation: str, sent_at: str) -> None:
        """Record external submission confirmation and timestamp."""
        self.confirmation = confirmation
        self.sent_at = sent_at

    def to_dict(self) -> dict[str, Any]:
        """Serialize regulatory notice fields to a plain dictionary."""
        return {
            "incident_id": self.incident_id,
            "detected_at": self.detected_at,
            "deadline_24h": self.deadline_24h,
            "deadline_72h": self.deadline_72h,
            "overdue_24h": self.overdue_24h,
            "overdue_72h": self.overdue_72h,
            "rkn_draft": self.rkn_draft,
            "is_auto_generated": self.is_auto_generated,
            "sent_at": self.sent_at,
            "confirmation": self.confirmation,
        }


@dataclass
class Notification:
    """Escalation or urgent alert delivered to a role or recipient."""

    id: int
    incident_id: int | None
    recipient_role: str
    recipient_name: str
    kind: str
    message: str
    created_at: str
    channel: str = Channel.INTERNAL
    status: str = DeliveryStatus.SENT

    def to_dict(self) -> dict[str, Any]:
        """Serialize notification fields to a plain dictionary."""
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "recipient_role": self.recipient_role,
            "recipient_name": self.recipient_name,
            "kind": self.kind,
            "message": self.message,
            "created_at": self.created_at,
            "channel": self.channel,
            "status": self.status,
        }


@dataclass
class AuditRecord:
    """Access-control and security audit trail entry."""

    id: int
    user_id: int | None
    object_type: str
    object_id: int | None
    action: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize audit record fields to a plain dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "action": self.action,
            "created_at": self.created_at,
        }


@dataclass
class IngestionError:
    """Failed signal ingestion log record."""

    id: int
    source: str
    error_text: str
    occurred_at: str
    resolved: bool = False

    def __post_init__(self) -> None:
        self.resolved = bool(self.resolved)

    def to_dict(self) -> dict[str, Any]:
        """Serialize ingestion error fields to a plain dictionary."""
        return {
            "id": self.id,
            "source": self.source,
            "error_text": self.error_text,
            "occurred_at": self.occurred_at,
            "resolved": self.resolved,
        }


@dataclass
class ReportFile:
    """Generated periodic incident report payload."""

    period: str
    format: ReportFormat
    created_at: str
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.format, str) and not isinstance(self.format, ReportFormat):
            self.format = ReportFormat(self.format.lower())

    def to_dict(self) -> dict[str, Any]:
        """Serialize report file metadata and data to a plain dictionary."""
        return {
            "period": self.period,
            "format": self.format,
            "created_at": self.created_at,
            "data": dict(self.data),
        }
