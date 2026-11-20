from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from app.domain.models import Deadlines, Incident, RegulatorNotice, ReportFile, User
from app.enums import (
    Channel,
    DeliveryStatus,
    IncidentStatus,
    PdnFlag,
    ReportFormat,
    Role,
    Severity,
    TaskStatus,
)
from app.integration.adapters import TelegramAdapter
from app.repositories.sqlite_repo import (
    HistoryRepository,
    IncidentRepository,
    InstructionRepository,
    NotificationRepository,
    TaskRepository,
    UserRepository,
    utc_now,
)
from app.services.access import AccessControlService
from app.services.exceptions import AccessDeniedError, NotFoundError, ValidationError, coerce_user


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
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_access(actor, incident, edit=True)

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
    """Task assignment, listing, completion, and overdue monitoring."""

    def __init__(
        self,
        task_repo: TaskRepository,
        incident_repo: IncidentRepository,
        user_repo: UserRepository,
        history_repo: HistoryRepository,
        access_control: AccessControlService,
    ) -> None:
        self.task_repo = task_repo
        self.incident_repo = incident_repo
        self.user_repo = user_repo
        self.history_repo = history_repo
        self.access_control = access_control

    def create_task(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a remediation task on an incident, defaulting assignee to sysadmin."""
        actor = coerce_user(user)
        incident = self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_access(actor, incident, edit=True)

        assigned_to = data.get("assigned_to")
        if assigned_to is None:
            sysadmin = self.user_repo.find_first_by_role(Role.SYS_ADMIN)
            assigned_to = sysadmin.id if sysadmin is not None else None

        now = utc_now()
        task = self.task_repo.create(
            incident_id=incident_id,
            title=str(data["title"]),
            description=str(data.get("description") or ""),
            assigned_to=assigned_to,
            created_by=actor.id,
            created_at=now,
            due_date=data.get("due_date"),
        )
        self.history_repo.add(
            incident_id=incident_id,
            user_id=actor.id,
            action="task_created",
            details=f"Создана задача #{task.id}: {task.title}",
            created_at=now,
        )
        self.access_control.log_access(actor.id, "task", task.id, "create")
        return task.to_dict()

    def list_tasks(
        self,
        user: User | Mapping[str, Any],
        assigned_to: str | int | None = None,
        status: str | None = None,
        incident_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """List tasks filtered by assignee, status, incident, and PDn access."""
        actor = coerce_user(user)
        exclude_pdn = not self.access_control.can_create_pdn(actor)

        assigned_id: int | None = None
        if assigned_to == "me":
            assigned_id = actor.id
        elif isinstance(assigned_to, int):
            assigned_id = assigned_to
        elif isinstance(assigned_to, str) and assigned_to.isdigit():
            assigned_id = int(assigned_to)

        return self.task_repo.list_filtered_with_meta(
            assigned_to=assigned_id,
            status=status,
            incident_id=incident_id,
            exclude_personal_data=exclude_pdn,
        )

    def update_task(
        self,
        user: User | Mapping[str, Any],
        task_id: int,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update task status, result, or due date with PDn RBAC check."""
        actor = coerce_user(user)
        found = self.task_repo.get_with_incident_pdn(task_id)
        if found is None:
            raise NotFoundError("Задача не найдена")

        task, has_pd = found
        if PdnFlag.from_bool_int(has_pd) is PdnFlag.YES and not self.access_control.can_create_pdn(actor):
            self.access_control.log_access(actor.id, "task", task_id, "access_denied")
            raise AccessDeniedError("Доступ к задачам по инцидентам с ПДн запрещен")

        now = utc_now()
        raw_status = data.get("status")
        raw_result = data.get("result")
        if "due_date" in data:
            task.due_date = data["due_date"]

        if raw_status is not None:
            norm_status = TaskStatus.normalize(raw_status)
            if TaskStatus.is_done(norm_status):
                res_val = str(raw_result) if raw_result is not None else task.result
                task.complete(res_val, task.completed_at or now)
            else:
                task.status = norm_status.value
                task.completed_at = None
                if raw_result is not None:
                    task.result = str(raw_result)
        elif raw_result is not None:
            task.result = str(raw_result)

        updated = self.task_repo.update(task)
        self.history_repo.add(
            incident_id=updated.incident_id,
            user_id=actor.id,
            action="task_updated",
            details=f"Задача #{task_id}: статус '{updated.status}'",
            created_at=now,
        )
        self.access_control.log_access(actor.id, "task", task_id, "update")
        return updated.to_dict()

    def list_overdue(self, user: User | Mapping[str, Any]) -> list[dict[str, Any]]:
        """Return overdue tasks visible to the user."""
        actor = coerce_user(user)
        exclude_pdn = not self.access_control.can_create_pdn(actor)
        now_dt = datetime.now(timezone.utc)
        tasks = self.task_repo.list_filtered(exclude_personal_data=exclude_pdn)
        return [task.to_dict() for task in tasks if task.is_overdue(now_dt)]


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

    def get_notice(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
    ) -> dict[str, Any]:
        """Compute RKN deadlines and auto-generate or return stored draft notice."""
        actor = coerce_user(user)
        self.access_control.assert_rkn_access(actor)
        incident = self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_access(actor, incident)
        self.access_control.log_access(actor.id, "regulator_notice", incident_id, "view")
        return self._build_notice(incident).to_dict()

    def update_draft(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
        rkn_draft: str,
    ) -> dict[str, Any]:
        """Persist an edited RKN notification draft."""
        actor = coerce_user(user)
        self.access_control.assert_rkn_access(actor)
        incident = self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_access(actor, incident, edit=True)

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
        actor = coerce_user(user)
        self.access_control.assert_rkn_access(actor)
        incident = self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_access(actor, incident, edit=True)

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
            self.telegram_adapter.send_message(recipient_name or role_val, message)

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
    ) -> None:
        self.incident_repo = incident_repo
        self.user_repo = user_repo
        self.history_repo = history_repo
        self.notification_service = notification_service
        self.notification_repo = notification_repo
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
                return self.notification_service.notify_urgent(
                    incident_id=incident.id,
                    recipient_role=role,
                    recipient_name=users_by_role.get(role.value, role.label),
                    kind=kind,
                    message=message,
                )
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

    def __init__(self, incident_repo: IncidentRepository) -> None:
        self.incident_repo = incident_repo

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
