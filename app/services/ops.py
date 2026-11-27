from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from app.domain.models import (
    MAX_TASK_ASSIGNEES,
    Deadlines,
    Incident,
    RegulatorNotice,
    ReportFile,
    Task,
    User,
)
from app.enums import (
    Channel,
    DeliveryStatus,
    IncidentStatus,
    IncidentType,
    PdnFlag,
    ReportFormat,
    Role,
    Severity,
    TaskStatus,
)
from app.integration.adapters import TelegramAdapter
from app.repositories.sqlite_repo import (
    AttachmentRepository,
    HistoryRepository,
    IncidentRepository,
    InstructionRepository,
    NotificationRepository,
    TaskRepository,
    UserRepository,
    utc_now,
)
from app.services.access import AccessControlService
from app.services.attachments import enrich_tasks_with_attachments
from app.services.dispatch import IncidentDispatcher
from app.services.exceptions import (
    AccessDeniedError,
    NotFoundError,
    ValidationError,
    coerce_user,
)
from app.services.users import enrich_tasks_with_users
from app.services.validators import (
    require_iso_datetime,
    require_non_blank,
    require_positive_int,
)

if TYPE_CHECKING:
    from app.services.telegram import TelegramNotificationService


def _parse_iso(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class InstructionService:
    """Response playbook listing and incident checklist step progress."""

    def __init__(
        self,
        incident_repo: IncidentRepository,
        instruction_repo: InstructionRepository,
        history_repo: HistoryRepository,
        access_control: AccessControlService,
    ) -> None:
        self.incident_repo = incident_repo
        self.instruction_repo = instruction_repo
        self.history_repo = history_repo
        self.access_control = access_control

    def list_instructions(self) -> list[dict[str, Any]]:
        """Return all response instruction templates."""
        return [inst.to_dict() for inst in self.instruction_repo.list_all()]

    def update_step(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
        step_index: int,
        completed: bool,
    ) -> dict[str, Any]:
        """Toggle completion state for an instruction step on an incident."""
        actor = coerce_user(user)
        incident = self.incident_repo.get_by_id(incident_id)
        self.access_control.assert_operational_incident_access(
            actor,
            incident,
            object_type="incident",
            object_id=incident_id,
            detail="Обновление шагов инструкции запрещено",
        )
        if incident is None:
            raise NotFoundError("Инцидент не найден")

        now = utc_now()
        progress = self.instruction_repo.upsert_progress(
            incident_id=incident_id,
            step_index=step_index,
            completed=completed,
            updated_by=actor.id,
            updated_at=now,
        )
        self.incident_repo.touch_updated_at(incident_id, now)
        state_label = "выполнен" if completed else "снят"
        self.history_repo.add(
            incident_id=incident_id,
            user_id=actor.id,
            action="step_updated",
            details=f"Шаг {step_index}: {state_label}",
            created_at=now,
        )
        self.access_control.log_access(actor.id, "incident", incident_id, "step_updated")
        return progress.to_dict()


class TaskService:
    """Task assignment (up to 3 assignees), listing, completion, and overdue monitoring."""

    def __init__(
        self,
        task_repo: TaskRepository,
        incident_repo: IncidentRepository,
        user_repo: UserRepository,
        history_repo: HistoryRepository,
        access_control: AccessControlService,
        attachment_repo: AttachmentRepository | None = None,
    ) -> None:
        self.task_repo = task_repo
        self.incident_repo = incident_repo
        self.user_repo = user_repo
        self.history_repo = history_repo
        self.access_control = access_control
        self.attachment_repo = attachment_repo or AttachmentRepository(task_repo.db)

    def _enrich_tasks(self, tasks: list[Any]) -> list[dict[str, Any]]:
        return enrich_tasks_with_attachments(
            enrich_tasks_with_users(tasks, self.user_repo),
            self.attachment_repo,
            self.user_repo,
        )

    def _validate_assignee(self, assigned_to: Any) -> User:
        """Validate that an explicit assignee ID belongs to an existing active user."""
        if isinstance(assigned_to, bool) or not isinstance(assigned_to, int) or assigned_to <= 0:
            raise ValidationError("Некорректный идентификатор исполнителя")
        assignee = self.user_repo.get_by_id(assigned_to)
        if assignee is None:
            raise NotFoundError("Исполнитель не найден")
        if not assignee.active:
            raise ValidationError("Нельзя назначить задачу неактивному пользователю")
        return assignee

    def _validate_assignee_ids(
        self,
        raw_ids: Any,
        *,
        allow_empty: bool = False,
    ) -> list[int]:
        """Validate a sequence of 0..3 (or 1..3) unique active assignee IDs."""
        if not isinstance(raw_ids, (list, tuple)):
            raise ValidationError("Поле 'assignee_ids' должно быть списком идентификаторов пользователей")
        unique_ids: list[int] = []
        seen: set[int] = set()
        for raw_id in raw_ids:
            assignee = self._validate_assignee(raw_id)
            if assignee.id not in seen:
                seen.add(assignee.id)
                unique_ids.append(assignee.id)
        if len(unique_ids) > MAX_TASK_ASSIGNEES:
            raise ValidationError(
                f"На задачу можно назначить не более {MAX_TASK_ASSIGNEES} исполнителей"
            )
        if not allow_empty and not unique_ids:
            raise ValidationError("Необходимо назначить хотя бы одного исполнителя")
        return unique_ids

    def _resolve_assignees_payload(
        self,
        data: Mapping[str, Any],
        *,
        allow_empty: bool,
    ) -> list[int]:
        """Resolve assignee_ids and/or legacy assigned_to fields consistently."""
        has_list = "assignee_ids" in data
        has_single = "assigned_to" in data

        if has_list and data["assignee_ids"] is not None:
            ids = self._validate_assignee_ids(data["assignee_ids"], allow_empty=allow_empty)
            if has_single and data["assigned_to"] is not None:
                primary = self._validate_assignee(data["assigned_to"]).id
                if primary not in ids:
                    raise ValidationError("Поля 'assigned_to' и 'assignee_ids' конфликтуют")
            return ids

        if has_list and data["assignee_ids"] is None:
            if not allow_empty:
                if has_single and data["assigned_to"] is not None:
                    return [self._validate_assignee(require_positive_int(data["assigned_to"], "assigned_to")).id]
                raise ValidationError("Необходимо назначить хотя бы одного исполнителя")
            if has_single and data["assigned_to"] is not None:
                raise ValidationError("Поля 'assigned_to' и 'assignee_ids' конфликтуют")
            return []

        if has_single:
            raw_assigned = data["assigned_to"]
            if raw_assigned is None:
                if not allow_empty:
                    raise ValidationError("Поле 'assigned_to' должно быть положительным целым числом")
                return []
            if not allow_empty:
                require_positive_int(raw_assigned, "assigned_to")
            return [self._validate_assignee(raw_assigned).id]

        raise ValidationError("Необходимо указать исполнителя задачи")

    @staticmethod
    def _format_assignee_history(assignee_ids: list[int]) -> str:
        if not assignee_ids:
            return "исполнитель снят"
        if len(assignee_ids) == 1:
            return f"исполнитель #{assignee_ids[0]}"
        return "исполнители: " + ", ".join(f"#{uid}" for uid in assignee_ids)

    def _load_editable_task(
        self,
        user: User | Mapping[str, Any],
        task_id: int,
        *,
        action: str = "edit_denied",
        detail: str = "Изменение задач запрещено",
    ) -> tuple[User, Task]:
        """Verify operational RBAC, task existence, and PDn visibility."""
        actor = coerce_user(user)
        self.access_control.assert_operational_access(
            actor,
            "task",
            task_id,
            action=action,
            detail=detail,
        )
        found = self.task_repo.get_with_incident_pdn(task_id)
        if found is None:
            raise NotFoundError("Задача не найдена")

        task, has_pd = found
        if PdnFlag.from_bool_int(has_pd) is PdnFlag.YES and not self.access_control.can_view_pdn(actor):
            self.access_control.log_access(actor.id, "task", task_id, "access_denied")
            raise AccessDeniedError("Доступ к задачам по инцидентам с ПДн запрещен")
        return actor, task

    def create_task(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a remediation task on an incident after validating required fields."""
        actor = coerce_user(user)
        incident = self.incident_repo.get_by_id(incident_id)
        self.access_control.assert_operational_incident_access(
            actor,
            incident,
            object_type="task",
            object_id=None,
            action="create_denied",
            detail="Создание задач запрещено",
        )
        if incident is None:
            raise NotFoundError("Инцидент не найден")

        if not isinstance(data, Mapping):
            raise ValidationError("Данные задачи должны быть словарём")

        title = require_non_blank(data.get("title"), "title")
        description = require_non_blank(data.get("description"), "description")
        assignee_ids = self._resolve_assignees_payload(data, allow_empty=False)
        due_date = require_iso_datetime(data.get("due_date"), "due_date")

        now = utc_now()
        task = self.task_repo.create(
            incident_id=incident_id,
            title=title,
            description=description,
            assigned_to=assignee_ids[0],
            assignee_ids=assignee_ids,
            created_by=actor.id,
            created_at=now,
            due_date=due_date,
        )
        self.history_repo.add(
            incident_id=incident_id,
            user_id=actor.id,
            action="task_created",
            details=f"Создана задача #{task.id}: {task.title}",
            created_at=now,
        )
        self.access_control.log_access(actor.id, "task", task.id, "create")
        return self._enrich_tasks([task])[0]

    def list_tasks(
        self,
        user: User | Mapping[str, Any],
        assigned_to: str | int | None = None,
        status: str | None = None,
        incident_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """List tasks filtered by assignee, status, incident, and PDn access."""
        actor = coerce_user(user)
        self.access_control.assert_task_view_access(actor)
        exclude_pdn = not self.access_control.can_view_pdn(actor)

        assigned_id: int | None = None
        if assigned_to == "me":
            assigned_id = actor.id
        elif isinstance(assigned_to, int):
            assigned_id = assigned_to
        elif isinstance(assigned_to, str) and assigned_to.isdigit():
            assigned_id = int(assigned_to)

        rows = self.task_repo.list_filtered_with_meta(
            assigned_to=assigned_id,
            status=status,
            incident_id=incident_id,
            exclude_personal_data=exclude_pdn,
        )
        return self._enrich_tasks(rows)

    def update_task(
        self,
        user: User | Mapping[str, Any],
        task_id: int,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update task status, result, assignees, or due date with RBAC and PDn check."""
        actor, task = self._load_editable_task(user, task_id)

        if not isinstance(data, Mapping):
            raise ValidationError("Данные обновления задачи должны быть словарём")

        now = utc_now()
        raw_status = data.get("status")
        raw_result = data.get("result")
        if raw_result is not None and not isinstance(raw_result, str):
            raise ValidationError("Поле 'result' должно быть строкой")
        if "due_date" in data:
            task.due_date = require_iso_datetime(data["due_date"], "due_date")

        reassigned = False
        if "assignee_ids" in data or "assigned_to" in data:
            new_assignee_ids = self._resolve_assignees_payload(data, allow_empty=True)
            task.set_assignees(new_assignee_ids)
            reassigned = True

        if raw_status is not None:
            try:
                norm_status = TaskStatus.normalize(raw_status)
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            if TaskStatus.is_done(norm_status):
                res_val = raw_result if raw_result is not None else task.result
                clean_result = require_non_blank(res_val, "result")
                task.complete(clean_result, task.completed_at or now)
            else:
                task.status = norm_status.value
                task.completed_at = None
                if raw_result is not None:
                    task.result = raw_result.strip() if raw_result.strip() else ""
        elif raw_result is not None:
            if TaskStatus.is_done(task.status):
                task.result = require_non_blank(raw_result, "result")
            else:
                task.result = raw_result.strip() if raw_result.strip() else ""

        updated = self.task_repo.update(task)
        details_parts = [f"Задача #{task_id}: статус '{updated.status}'"]
        if reassigned:
            details_parts.append(self._format_assignee_history(updated.assignee_ids))
        self.history_repo.add(
            incident_id=updated.incident_id,
            user_id=actor.id,
            action="task_updated",
            details=", ".join(details_parts),
            created_at=now,
        )
        self.access_control.log_access(actor.id, "task", task_id, "update")
        return self._enrich_tasks([updated])[0]

    def set_assignees(
        self,
        user: User | Mapping[str, Any],
        task_id: int,
        assignee_ids: list[int] | None,
    ) -> dict[str, Any]:
        """Replace the full list of task assignees (0..3 active users)."""
        actor, task = self._load_editable_task(user, task_id)
        raw_list = [] if assignee_ids is None else assignee_ids
        validated_ids = self._validate_assignee_ids(raw_list, allow_empty=True)
        task.set_assignees(validated_ids)
        updated = self.task_repo.update(task)
        now = utc_now()
        self.history_repo.add(
            incident_id=updated.incident_id,
            user_id=actor.id,
            action="task_updated",
            details=f"Задача #{task_id}: {self._format_assignee_history(updated.assignee_ids)}",
            created_at=now,
        )
        self.access_control.log_access(actor.id, "task", task_id, "update")
        return self._enrich_tasks([updated])[0]

    def add_assignee(
        self,
        user: User | Mapping[str, Any],
        task_id: int,
        user_id: Any,
    ) -> dict[str, Any]:
        """Add an active assignee to a task if not already assigned and below MAX_TASK_ASSIGNEES."""
        actor, task = self._load_editable_task(user, task_id)
        assignee = self._validate_assignee(user_id)
        try:
            added = task.add_assignee(assignee.id)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

        if added:
            updated = self.task_repo.update(task)
            self.history_repo.add(
                incident_id=updated.incident_id,
                user_id=actor.id,
                action="task_updated",
                details=f"Задача #{task_id}: добавлен исполнитель #{assignee.id}",
                created_at=utc_now(),
            )
        else:
            updated = task
        self.access_control.log_access(actor.id, "task", task_id, "update")
        return self._enrich_tasks([updated])[0]

    def remove_assignee(
        self,
        user: User | Mapping[str, Any],
        task_id: int,
        user_id: int,
    ) -> dict[str, Any]:
        """Remove an assignee from a task, shifting primary assigned_to to the next assignee."""
        actor, task = self._load_editable_task(user, task_id)
        target_id = require_positive_int(user_id, "user_id")
        if not task.remove_assignee(target_id):
            raise NotFoundError("Исполнитель не назначен на эту задачу")
        updated = self.task_repo.update(task)
        self.history_repo.add(
            incident_id=updated.incident_id,
            user_id=actor.id,
            action="task_updated",
            details=f"Задача #{task_id}: снят исполнитель #{target_id}",
            created_at=utc_now(),
        )
        self.access_control.log_access(actor.id, "task", task_id, "update")
        return self._enrich_tasks([updated])[0]

    def list_overdue(self, user: User | Mapping[str, Any]) -> list[dict[str, Any]]:
        """Return overdue tasks visible to the user."""
        actor = coerce_user(user)
        self.access_control.assert_task_view_access(actor)
        exclude_pdn = not self.access_control.can_view_pdn(actor)
        now_dt = datetime.now(timezone.utc)
        tasks = self.task_repo.list_filtered(exclude_personal_data=exclude_pdn)
        overdue = [task for task in tasks if task.is_overdue(now_dt)]
        return self._enrich_tasks(overdue)


class DeadlineService:
    """Roskomnadzor 24h/72h deadline calculation and regulatory notice management."""

    def __init__(
        self,
        incident_repo: IncidentRepository,
        history_repo: HistoryRepository,
        access_control: AccessControlService,
    ) -> None:
        self.incident_repo = incident_repo
        self.history_repo = history_repo
        self.access_control = access_control

    def calculate(self, detected_at: str) -> Deadlines:
        """Compute 24h and 72h reporting deadlines and overdue flags."""
        detected_dt = _parse_iso(detected_at)
        deadline_24h = (detected_dt + timedelta(hours=24)).replace(microsecond=0)
        deadline_72h = (detected_dt + timedelta(hours=72)).replace(microsecond=0)
        now = datetime.now(timezone.utc)
        return Deadlines(
            detected_at=detected_at,
            deadline_24h=deadline_24h.isoformat(),
            deadline_72h=deadline_72h.isoformat(),
            overdue_24h=now > deadline_24h,
            overdue_72h=now > deadline_72h,
        )

    def remaining(self, deadline: str) -> timedelta:
        """Return time remaining until the deadline (negative if overdue)."""
        return _parse_iso(deadline) - datetime.now(timezone.utc)

    def _build_notice(self, incident: Incident) -> RegulatorNotice:
        deadlines = self.calculate(incident.detected_at)
        stored_draft = incident.rkn_draft or ""
        is_auto = not bool(stored_draft.strip())
        draft = (
            RegulatorNotice.build_draft(incident, deadlines.deadline_24h, deadlines.deadline_72h)
            if is_auto
            else stored_draft
        )
        return RegulatorNotice(
            incident_id=incident.id or 0,
            detected_at=incident.detected_at,
            deadline_24h=deadlines.deadline_24h,
            deadline_72h=deadlines.deadline_72h,
            overdue_24h=deadlines.overdue_24h,
            overdue_72h=deadlines.overdue_72h,
            rkn_draft=draft,
            is_auto_generated=is_auto,
            sent_at=incident.rkn_sent_at,
            confirmation=incident.rkn_confirmation,
        )

    def _load_authorized_rkn_incident(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
        *,
        edit: bool = False,
    ) -> tuple[User, Incident]:
        actor = coerce_user(user)
        self.access_control.assert_rkn_access(actor)
        incident = self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_rkn_access(actor, incident)
        self.access_control.assert_incident_access(actor, incident, edit=edit)
        return actor, incident

    def get_notice(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
    ) -> dict[str, Any]:
        """Compute RKN deadlines and auto-generate or return stored draft notice."""
        actor, incident = self._load_authorized_rkn_incident(user, incident_id, edit=False)
        self.access_control.log_access(actor.id, "regulator_notice", incident_id, "view")
        return self._build_notice(incident).to_dict()

    def update_draft(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
        rkn_draft: str,
    ) -> dict[str, Any]:
        """Persist an edited RKN notification draft."""
        actor, incident = self._load_authorized_rkn_incident(user, incident_id, edit=True)

        now = utc_now()
        incident.rkn_draft = rkn_draft
        incident.updated_at = now
        updated = self.incident_repo.update(incident)
        self.history_repo.add(
            incident_id=incident_id,
            user_id=actor.id,
            action="rkn_draft_updated",
            details="Обновлен черновик уведомления в РКН",
            created_at=now,
        )
        self.access_control.log_access(actor.id, "regulator_notice", incident_id, "update_draft")
        return self._build_notice(updated).to_dict()

    def mark_sent(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
        confirmation: str,
    ) -> dict[str, Any]:
        """Record RKN notice submission confirmation and timestamp."""
        actor, incident = self._load_authorized_rkn_incident(user, incident_id, edit=True)

        now = utc_now()
        notice = self._build_notice(incident)
        notice.mark_sent(confirmation, now)

        if not (incident.rkn_draft or "").strip():
            incident.rkn_draft = notice.rkn_draft
        incident.rkn_sent_at = notice.sent_at
        incident.rkn_confirmation = notice.confirmation
        incident.updated_at = now

        updated = self.incident_repo.update(incident)
        self.history_repo.add(
            incident_id=incident_id,
            user_id=actor.id,
            action="rkn_sent",
            details=f"Уведомление в РКН отправлено ({confirmation or 'без подтверждения'})",
            created_at=now,
        )
        self.access_control.log_access(actor.id, "regulator_notice", incident_id, "mark_sent")
        return self._build_notice(updated).to_dict()


class NotificationService:
    """Urgent alerts, notification feed, and broadcast warnings."""

    def __init__(
        self,
        notification_repo: NotificationRepository,
        user_repo: UserRepository,
        telegram_adapter: TelegramAdapter | None = None,
    ) -> None:
        self.notification_repo = notification_repo
        self.user_repo = user_repo
        self.telegram_adapter = telegram_adapter

    def notify_urgent(
        self,
        incident_id: int | None,
        recipient_role: Role | str,
        recipient_name: str,
        kind: str,
        message: str,
        channel: Channel | str = Channel.INTERNAL,
    ) -> dict[str, Any] | None:
        """Create a deduplicated urgent notification and optionally deliver via channel."""
        role_val = recipient_role.value if isinstance(recipient_role, Role) else str(recipient_role)
        channel_enum = channel if isinstance(channel, Channel) else Channel(str(channel).lower())
        now = utc_now()

        if incident_id is not None:
            notif = self.notification_repo.create_if_new(
                incident_id=incident_id,
                recipient_role=role_val,
                recipient_name=recipient_name,
                kind=kind,
                message=message,
                created_at=now,
                channel=channel_enum.value,
                status=DeliveryStatus.SENT.value,
            )
            if notif is None:
                return None
        else:
            notif = self.notification_repo.create(
                incident_id=None,
                recipient_role=role_val,
                recipient_name=recipient_name,
                kind=kind,
                message=message,
                created_at=now,
                channel=channel_enum.value,
                status=DeliveryStatus.SENT.value,
            )

        if channel_enum is Channel.TELEGRAM and self.telegram_adapter is not None:
            ok = self.telegram_adapter.send_message(recipient_name or role_val, message)
            if not ok:
                self.notification_repo.update_status(notif.id, DeliveryStatus.FAILED)
                notif.status = DeliveryStatus.FAILED.value

        return notif.to_dict()

    def list_notifications(
        self,
        recipient_role: Role | str | None = None,
        q: str | None = None,
        kind: str | None = None,
        incident_id: int | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[dict[str, Any]]:
        """List notifications ordered newest first, optionally filtered by search and facets."""
        if isinstance(recipient_role, Role):
            role_val: str | None = recipient_role.value
        elif isinstance(recipient_role, str):
            role_val = recipient_role.strip() or None
        else:
            role_val = None
        try:
            items = self.notification_repo.list_all(
                recipient_role=role_val,
                q=q,
                kind=kind,
                incident_id=incident_id,
                date_from=date_from,
                date_to=date_to,
            )
        except ValueError as exc:
            raise ValidationError(f"Некорректный формат даты: {exc}") from exc
        return [n.to_dict() for n in items]

    def broadcast_warning(self, text: str, recipients: list[str]) -> list[dict[str, Any]]:
        """Send an internal warning broadcast to a list of roles or usernames."""
        names_by_role = self.user_repo.get_names_by_role()
        now = utc_now()
        created: list[dict[str, Any]] = []

        for recipient in recipients:
            target = str(recipient).strip()
            if not target:
                continue
            try:
                role = Role(target)
                role_val = role.value
                display_name = names_by_role.get(role_val, role.label)
            except ValueError:
                user = self.user_repo.get_by_username(target)
                if user is not None:
                    role_val = user.role.value if isinstance(user.role, Role) else str(user.role)
                    display_name = user.full_name
                else:
                    role_val = target
                    display_name = target

            notif = self.notification_repo.create(
                incident_id=None,
                recipient_role=role_val,
                recipient_name=display_name,
                kind="warning_broadcast",
                message=text,
                created_at=now,
                channel=Channel.INTERNAL.value,
                status=DeliveryStatus.SENT.value,
            )
            created.append(notif.to_dict())

        return created


class EscalationService:
    """Timeout-based escalation rules and PDn regulatory notifications."""

    timeout_min: int = 30

    def __init__(
        self,
        incident_repo: IncidentRepository,
        user_repo: UserRepository,
        history_repo: HistoryRepository,
        notification_service: NotificationService,
        notification_repo: NotificationRepository,
        telegram_service: "TelegramNotificationService | None" = None,
    ) -> None:
        self.incident_repo = incident_repo
        self.user_repo = user_repo
        self.history_repo = history_repo
        self.notification_service = notification_service
        self.notification_repo = notification_repo
        self.telegram_service = telegram_service
        self._stopped_keys: set[tuple[str, int]] = set()

    def _is_stopped(self, incident: Incident) -> bool:
        if incident.id is None:
            return False
        if (self.incident_repo.db.resolve_path(), incident.id) in self._stopped_keys:
            return True
        if incident.status != IncidentStatus.NEW.value or incident.taken_at is not None:
            return True
        return any(
            h.action == "escalation_stopped"
            for h in self.history_repo.list_by_incident(incident.id)
        )

    def _escalation_30m_message(self, incident: Incident) -> str:
        return (
            f"Эскалация: инцидент #{incident.id} «{incident.title}» "
            f"(критичность: {incident.severity}) не взят в работу более {self.timeout_min} минут."
        )

    def _escalate_unaccepted(
        self,
        *,
        high_severity_only: bool,
        include_pdn_notices: bool,
    ) -> list[dict[str, Any]]:
        now_dt = datetime.now(timezone.utc)
        threshold = now_dt - timedelta(minutes=self.timeout_min)
        users_by_role = self.user_repo.get_names_by_role()
        it_head_name = users_by_role.get(Role.IT_HEAD.value, Role.IT_HEAD.label)
        lawyer_name = users_by_role.get(Role.LAWYER.value, Role.LAWYER.label)
        acc_name = users_by_role.get(Role.ACCOUNTANT.value, Role.ACCOUNTANT.label)

        created: list[dict[str, Any]] = []
        for inc in self.incident_repo.list_open():
            detected_dt = _parse_iso(inc.detected_at)
            is_unaccepted_overdue = (
                inc.taken_at is None
                and inc.status == IncidentStatus.NEW.value
                and detected_dt < threshold
                and not self._is_stopped(inc)
            )
            if is_unaccepted_overdue:
                should_notify = True
                if high_severity_only:
                    should_notify = (
                        Severity.normalize(inc.severity).weight >= Severity.HIGH.weight
                    )
                if should_notify:
                    notif = self.notification_service.notify_urgent(
                        incident_id=inc.id,
                        recipient_role=Role.IT_HEAD,
                        recipient_name=it_head_name,
                        kind="escalation_30m",
                        message=self._escalation_30m_message(inc),
                    )
                    if notif is not None:
                        created.append(notif)
                        if self.telegram_service is not None:
                            self.telegram_service.notify_escalation(
                                inc,
                                Role.IT_HEAD,
                                "escalation_30m",
                                self._escalation_30m_message(inc),
                            )

            if include_pdn_notices and PdnFlag.from_bool_int(inc.has_personal_data) is PdnFlag.YES:
                lawyer_msg = (
                    f"Срочно (ПДн): инцидент #{inc.id} «{inc.title}» требует правовой оценки "
                    f"и подготовки уведомления в РКН (24ч/72ч)."
                )
                lawyer_notif = self.notification_service.notify_urgent(
                    incident_id=inc.id,
                    recipient_role=Role.LAWYER,
                    recipient_name=lawyer_name,
                    kind="pdn_lawyer_notice",
                    message=lawyer_msg,
                )
                if lawyer_notif is not None:
                    created.append(lawyer_notif)
                    if self.telegram_service is not None:
                        self.telegram_service.notify_escalation(
                            inc,
                            Role.LAWYER,
                            "pdn_lawyer_notice",
                            lawyer_msg,
                        )

                acc_msg = (
                    f"Уведомление (ПДн): инцидент #{inc.id} «{inc.title}» затрагивает ПДн — "
                    f"оценить риски и возможные регуляторные последствия."
                )
                acc_notif = self.notification_service.notify_urgent(
                    incident_id=inc.id,
                    recipient_role=Role.ACCOUNTANT,
                    recipient_name=acc_name,
                    kind="pdn_accounting_notice",
                    message=acc_msg,
                )
                if acc_notif is not None:
                    created.append(acc_notif)
                    if self.telegram_service is not None:
                        self.telegram_service.notify_escalation(
                            inc,
                            Role.ACCOUNTANT,
                            "pdn_accounting_notice",
                            acc_msg,
                        )

        return created

    def check_unaccepted_high_severity(self) -> list[dict[str, Any]]:
        """Escalate unaccepted high/critical incidents past timeout_min."""
        return self._escalate_unaccepted(
            high_severity_only=True,
            include_pdn_notices=False,
        )

    def check_escalations(self) -> list[dict[str, Any]]:
        """Run full escalation check (30m timeout + PDn lawyer/accountant notices)."""
        return self._escalate_unaccepted(
            high_severity_only=False,
            include_pdn_notices=True,
        )

    def call_next(self, incident: Incident) -> dict[str, Any] | None:
        """Send the next escalation step in the chain for an unaccepted incident."""
        if incident.id is None or self._is_stopped(incident):
            return None

        users_by_role = self.user_repo.get_names_by_role()
        chain: tuple[tuple[Role, str, str], ...] = (
            (
                Role.IT_HEAD,
                "escalation_30m",
                self._escalation_30m_message(incident),
            ),
            (
                Role.DIRECTOR,
                "escalation_director",
                (
                    f"Повторная эскалация: инцидент #{incident.id} «{incident.title}» "
                    f"не взят в работу и передан директору."
                ),
            ),
        )
        for role, kind, message in chain:
            if not self.notification_repo.exists(incident.id, kind):
                notif = self.notification_service.notify_urgent(
                    incident_id=incident.id,
                    recipient_role=role,
                    recipient_name=users_by_role.get(role.value, role.label),
                    kind=kind,
                    message=message,
                )
                if notif is not None and self.telegram_service is not None:
                    self.telegram_service.notify_escalation(incident, role, kind, message)
                return notif
        return None

    def stop(self, incident: Incident) -> None:
        """Stop further automated escalations for an incident."""
        if incident.id is None:
            return
        self._stopped_keys.add((self.incident_repo.db.resolve_path(), incident.id))
        if self.incident_repo.get_by_id(incident.id) is not None:
            self.history_repo.add(
                incident_id=incident.id,
                user_id=None,
                action="escalation_stopped",
                details="Эскалация остановлена",
            )


class ReportService:
    """Periodic incident aggregation and report export."""

    def __init__(
        self,
        incident_repo: IncidentRepository,
        dispatcher: IncidentDispatcher | None = None,
    ) -> None:
        self.incident_repo = incident_repo
        self.dispatcher = dispatcher if dispatcher is not None else IncidentDispatcher()

    @staticmethod
    def _aggregate_incidents(incidents: list[Incident]) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        pdn_count = 0

        for inc in incidents:
            by_type[inc.incident_type] = by_type.get(inc.incident_type, 0) + 1
            by_status[inc.status] = by_status.get(inc.status, 0) + 1
            outcome_key = inc.outcome or "Без итога"
            by_outcome[outcome_key] = by_outcome.get(outcome_key, 0) + 1
            by_severity[inc.severity] = by_severity.get(inc.severity, 0) + 1
            if PdnFlag.from_bool_int(inc.has_personal_data) is PdnFlag.YES:
                pdn_count += 1

        return {
            "total": len(incidents),
            "personal_data_count": pdn_count,
            "by_incident_type": by_type,
            "by_status": by_status,
            "by_outcome": by_outcome,
            "by_severity": by_severity,
        }

    def monthly_report(
        self,
        year: int | None = None,
        month: int | None = None,
    ) -> dict[str, Any]:
        """Aggregate unique incidents detected in a given month."""
        now_dt = datetime.now(timezone.utc)
        target_year = year if year is not None else now_dt.year
        target_month = month if month is not None else now_dt.month
        incidents = self.incident_repo.list_by_month(target_year, target_month)
        stats = self._aggregate_incidents(incidents)
        return {
            "year": target_year,
            "month": target_month,
            **stats,
        }

    def year_stats(self, year: int | None = None) -> dict[str, Any]:
        """Aggregate unique incidents across a full calendar year."""
        now_dt = datetime.now(timezone.utc)
        target_year = year if year is not None else now_dt.year
        incidents = self.incident_repo.list_by_year(target_year)
        stats = self._aggregate_incidents(incidents)
        by_month: dict[str, int] = {}
        for inc in incidents:
            ym = inc.detected_at[:7]
            if ym:
                by_month[ym] = by_month.get(ym, 0) + 1
        return {
            "year": target_year,
            "by_month": by_month,
            **stats,
        }

    def by_type_report(
        self,
        year: int | None = None,
        month: int | None = None,
    ) -> dict[str, Any]:
        """Return incident distribution by type, access category, severity, and responsible role."""
        if year is not None and month is not None:
            incidents = self.incident_repo.list_by_month(year, month)
        elif year is not None:
            incidents = self.incident_repo.list_by_year(year)
        else:
            incidents = self.incident_repo.list_filtered()

        by_incident_type: dict[str, int] = {}
        by_access_category: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_responsible_role: dict[str, int] = {}
        pdn_count = 0

        for inc in incidents:
            norm_type = IncidentType.normalize(inc.incident_type).value
            by_incident_type[norm_type] = by_incident_type.get(norm_type, 0) + 1

            access_cat = inc.access_category or self.dispatcher.resolve_access_category(
                norm_type,
                has_personal_data=inc.has_personal_data,
                employee=inc.employee,
            ).value
            by_access_category[access_cat] = by_access_category.get(access_cat, 0) + 1

            by_severity[inc.severity] = by_severity.get(inc.severity, 0) + 1

            role = self.dispatcher.get_rule(norm_type).responsible_role.value
            by_responsible_role[role] = by_responsible_role.get(role, 0) + 1

            if PdnFlag.from_bool_int(inc.has_personal_data) is PdnFlag.YES:
                pdn_count += 1

        return {
            "total": len(incidents),
            "personal_data_count": pdn_count,
            "by_incident_type": by_incident_type,
            "by_access_category": by_access_category,
            "by_severity": by_severity,
            "by_responsible_role": by_responsible_role,
        }

    def export_report(
        self,
        period: str,
        fmt: ReportFormat | str,
        data: dict[str, Any],
    ) -> ReportFile:
        """Package report statistics into a ReportFile domain descriptor."""
        report_fmt = fmt if isinstance(fmt, ReportFormat) else ReportFormat(str(fmt).lower())
        return ReportFile(
            period=period,
            format=report_fmt,
            created_at=utc_now(),
            data=dict(data),
        )
