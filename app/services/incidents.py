from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from app.domain.models import Incident, User
from app.enums import (
    CheckResult,
    IncidentStatus,
    IncidentType,
    PdnFlag,
    Severity,
    SourceType,
)
from app.integration.adapters import ADAPTER_REGISTRY, SourceAdapter, TelegramAdapter
from app.repositories.sqlite_repo import (
    DEFAULT_INCIDENT_SORT_BY,
    DEFAULT_INCIDENT_SORT_ORDER,
    HistoryRepository,
    IncidentRepository,
    IngestionErrorRepository,
    InstructionRepository,
    MessageRepository,
    TaskRepository,
    UserRepository,
    resolve_incident_sort,
    utc_now,
)
from app.services.access import AccessControlService
from app.services.dispatch import IncidentDispatcher
from app.services.exceptions import (
    AccessDeniedError,
    NotFoundError,
    ValidationError,
    coerce_user,
)
from app.services.ops import NotificationService
from app.services.users import enrich_tasks_with_users
from app.services.validators import require_non_blank, require_non_blank_enum_input

if TYPE_CHECKING:
    from app.services.telegram import TelegramNotificationService


def normalize_outcome(raw: str | CheckResult | None) -> str | None:
    """Normalize a CheckResult value or alias, preserving custom outcome strings."""
    if raw is None:
        return None
    if isinstance(raw, CheckResult):
        return raw.value
    if not isinstance(raw, str):
        raise ValidationError("Поле 'outcome' должно быть строкой")
    cleaned = raw.strip()
    if not cleaned:
        return ""
    try:
        return CheckResult.normalize(cleaned).value
    except ValueError:
        return cleaned


def _normalize_unregistered_signal(
    raw: dict[str, Any],
    source_value: str,
) -> dict[str, Any]:
    raw_type = raw.get("incident_type")
    if raw_type is not None and str(raw_type).strip():
        incident_type = IncidentType.normalize(str(raw_type)).value
    else:
        incident_type = IncidentType.OTHER.value

    raw_sev = raw.get("severity")
    if raw_sev is not None and str(raw_sev).strip():
        severity = Severity.normalize(raw_sev).value
    else:
        severity = Severity.MEDIUM.value

    pdn = PdnFlag.from_bool_int(raw.get("has_personal_data", 0)).to_bool_int()
    raw_title = raw.get("title")
    title = str(raw_title).strip() if raw_title is not None else ""

    return {
        "source": source_value,
        "sender": str(raw.get("sender") or "").strip(),
        "body": str(raw.get("body") or raw.get("message") or raw.get("text") or "").strip(),
        "computer": str(raw.get("computer") or raw.get("host") or "").strip(),
        "employee": str(raw.get("employee") or "").strip(),
        "incident_type": incident_type,
        "severity": severity,
        "incident_key": str(raw.get("incident_key") or "").strip(),
        "has_personal_data": pdn,
        "title": title or None,
    }


class DeduplicationService:
    """Signal deduplication and merging against open incidents."""

    def __init__(
        self,
        incident_repo: IncidentRepository,
        message_repo: MessageRepository,
        history_repo: HistoryRepository,
    ) -> None:
        self.incident_repo = incident_repo
        self.message_repo = message_repo
        self.history_repo = history_repo

    def find_related(
        self,
        incident_key: str,
        computer: str,
        incident_type: str,
    ) -> Incident | None:
        """Locate an active incident matching key or (computer, incident_type)."""
        key = (incident_key or "").strip()
        comp = (computer or "").strip()
        raw_type = (incident_type or "").strip()
        norm_type = IncidentType.normalize(raw_type).value if raw_type else ""

        if key:
            by_key = self.incident_repo.find_open_by_key(key)
            if by_key is not None:
                return by_key
        if comp and norm_type:
            return self.incident_repo.find_open_by_computer_and_type(comp, norm_type)
        return None

    def is_duplicate(
        self,
        incident_key: str,
        computer: str,
        incident_type: str,
    ) -> bool:
        """Return True if an open incident matches the incoming signal."""
        return self.find_related(incident_key, computer, incident_type) is not None

    def merge(
        self,
        existing: Incident,
        message_data: dict[str, Any],
    ) -> tuple[Incident, int]:
        """Attach a duplicate signal message to an existing open incident."""
        if existing.id is None:
            raise ValueError("Existing incident must have an id before merging")

        now = utc_now()
        source = str(message_data.get("source") or "")
        sender = str(message_data.get("sender") or "")
        body = str(message_data.get("body") or "")
        incident_key = str(message_data.get("incident_key") or "").strip()

        self.incident_repo.touch_updated_at(existing.id, now)
        msg = self.message_repo.create(
            incident_id=existing.id,
            source=source,
            sender=sender,
            body=body,
            incident_key=incident_key,
            received_at=now,
        )

        origin = source or sender or "external"
        self.history_repo.add(
            incident_id=existing.id,
            user_id=None,
            action="signal_deduplicated",
            details=f"Повторный сигнал ({origin}) привязан к инциденту",
            created_at=now,
        )
        updated = self.incident_repo.get_by_id(existing.id) or existing
        return updated, msg.id


class IngestionService:
    """Signal normalization, error logging, and manual incident registration."""

    def __init__(
        self,
        incident_repo: IncidentRepository,
        message_repo: MessageRepository,
        history_repo: HistoryRepository,
        instruction_repo: InstructionRepository,
        ingestion_error_repo: IngestionErrorRepository,
        deduplication_service: DeduplicationService,
        access_control: AccessControlService,
        adapters: Mapping[SourceType, SourceAdapter] | None = None,
        dispatcher: IncidentDispatcher | None = None,
        user_repo: UserRepository | None = None,
        notification_service: NotificationService | None = None,
        telegram_service: "TelegramNotificationService | None" = None,
    ) -> None:
        self.incident_repo = incident_repo
        self.message_repo = message_repo
        self.history_repo = history_repo
        self.instruction_repo = instruction_repo
        self.ingestion_error_repo = ingestion_error_repo
        self.deduplication = deduplication_service
        self.access_control = access_control
        self.adapters = dict(adapters) if adapters is not None else dict(ADAPTER_REGISTRY)
        self.dispatcher = dispatcher if dispatcher is not None else IncidentDispatcher()
        self.user_repo = user_repo
        self.notification_service = notification_service
        self.telegram_service = telegram_service

    def receive(self, signal_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize an external signal, classify & dispatch, deduplicate or create incident."""
        raw_source = (
            str(signal_data.get("source") or "").strip()
            if isinstance(signal_data, dict)
            else ""
        )
        source_enum: SourceType | None = SourceType.normalize(raw_source) if raw_source else None

        try:
            if not isinstance(signal_data, dict):
                raise ValueError("Signal payload must be a dictionary")

            adapter = self.adapters.get(source_enum) if source_enum is not None else None
            if adapter is not None:
                normalized = adapter.normalize(signal_data)
            else:
                normalized = _normalize_unregistered_signal(
                    signal_data,
                    source_enum.value if source_enum is not None else "",
                )

            if not str(normalized.get("body") or "").strip():
                raise ValueError("Signal body must not be empty")

            raw_assigned = signal_data.get("assigned_to")
            assigned_to: int | None = int(raw_assigned) if raw_assigned is not None else None
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            self.ingestion_error_repo.create(
                source=raw_source or "unknown",
                error_text=str(exc),
            )
            raise ValidationError(f"Некорректный формат сигнала: {exc}") from exc

        raw_incident_type = signal_data.get("incident_type")
        error_code = str(signal_data.get("error_code") or "").strip()
        classified_type = self.dispatcher.classify_signal(
            body=normalized["body"],
            incident_type=str(raw_incident_type) if raw_incident_type is not None else None,
            source=normalized["source"] or raw_source,
            error_code=error_code,
        )
        incident_type = classified_type.value
        rule = self.dispatcher.get_rule(classified_type)

        raw_severity = signal_data.get("severity")
        if raw_severity is not None and str(raw_severity).strip():
            severity = normalized["severity"]
        else:
            severity = rule.default_severity.value

        has_personal_data = normalized["has_personal_data"]
        if classified_type is IncidentType.DATA_LEAK:
            has_personal_data = 1

        access_category = self.dispatcher.resolve_access_category(
            classified_type,
            has_personal_data=has_personal_data,
            employee=normalized["employee"],
        ).value

        if assigned_to is None and self.user_repo is not None:
            assignee = self.user_repo.find_first_by_role(rule.responsible_role)
            if assignee is not None:
                assigned_to = assignee.id

        existing = self.deduplication.find_related(
            normalized["incident_key"],
            normalized["computer"],
            incident_type,
        )
        if existing is not None:
            merged, message_id = self.deduplication.merge(existing, normalized)
            self._notify_telegram_reply(source_enum, signal_data, merged.id)
            return {
                "incident_id": merged.id,
                "deduplicated": True,
                "message_id": message_id,
            }

        now = utc_now()
        origin = normalized["source"] or normalized["sender"] or "external"
        title = (
            normalized["title"]
            or f"{incident_type}: {normalized['computer'] or normalized['sender'] or origin}"
        )
        instruction_id = self.instruction_repo.find_default_id(incident_type)

        incident = Incident(
            title=title,
            description=normalized["body"],
            incident_type=incident_type,
            severity=severity,
            status=IncidentStatus.NEW.value,
            computer=normalized["computer"],
            employee=normalized["employee"],
            source=normalized["source"],
            incident_key=normalized["incident_key"],
            has_personal_data=has_personal_data,
            instruction_id=instruction_id,
            detected_at=now,
            created_at=now,
            updated_at=now,
            access_category=access_category,
            assigned_to=assigned_to,
        )
        created = self.incident_repo.create(incident)
        msg = self.message_repo.create(
            incident_id=created.id,
            source=normalized["source"],
            sender=normalized["sender"],
            body=normalized["body"],
            incident_key=normalized["incident_key"],
            received_at=now,
        )
        self.history_repo.add(
            incident_id=created.id,
            user_id=None,
            action="signal_created",
            details=f"Инцидент создан по сигналу ({origin})",
            created_at=now,
        )
        self._emit_urgent_notifications(created, classified_type, severity)
        self._notify_telegram_reply(source_enum, signal_data, created.id)
        if self.telegram_service is not None:
            self.telegram_service.notify_incident_created(created)
        return {
            "incident_id": created.id,
            "deduplicated": False,
            "message_id": msg.id,
        }

    def _emit_urgent_notifications(
        self,
        incident: Incident,
        incident_type: IncidentType,
        severity: str,
    ) -> None:
        if self.notification_service is None or incident.id is None:
            return
        urgent_roles = self.dispatcher.resolve_urgent_roles(incident_type, severity)
        if not urgent_roles:
            return

        names_by_role = self.user_repo.get_names_by_role() if self.user_repo is not None else {}
        for role in urgent_roles:
            recipient_name = names_by_role.get(role.value, role.label)
            self.notification_service.notify_urgent(
                incident_id=incident.id,
                recipient_role=role,
                recipient_name=recipient_name,
                kind=f"urgent_dispatch_{role.value}",
                message=(
                    f"Срочно ({incident_type.value}, критичность: {severity}): "
                    f"инцидент #{incident.id} «{incident.title}»."
                ),
            )

    def _notify_telegram_reply(
        self,
        source_enum: SourceType | None,
        signal_data: dict[str, Any],
        incident_id: int | None,
    ) -> None:
        if source_enum is not SourceType.TELEGRAM or incident_id is None:
            return
        chat_id = signal_data.get("chat_id")
        adapter = self.adapters.get(SourceType.TELEGRAM)
        if chat_id and isinstance(adapter, TelegramAdapter):
            adapter.reply_number(str(chat_id), incident_id)

    def register_manually(
        self,
        data: dict[str, Any],
        user: User | Mapping[str, Any],
    ) -> dict[str, Any]:
        """Create an incident manually after checking RBAC and PDn permissions."""
        actor = coerce_user(user)
        if not isinstance(data, Mapping):
            raise ValidationError("Данные инцидента должны быть словарём")

        try:
            has_pd = PdnFlag.from_bool_int(data.get("has_personal_data", 0)).to_bool_int()
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        self.access_control.assert_create_incident_access(
            actor,
            has_personal_data=bool(has_pd),
        )

        title = require_non_blank(data.get("title"), "title")
        description = require_non_blank(data.get("description"), "description")
        raw_type = require_non_blank_enum_input(
            data.get("incident_type"), IncidentType, "incident_type"
        )
        raw_source = require_non_blank_enum_input(data.get("source"), SourceType, "source")

        incident_type = IncidentType.normalize(raw_type).value
        source = SourceType.normalize(raw_source).value
        try:
            severity = Severity.normalize(data.get("severity", Severity.MEDIUM)).value
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

        now = utc_now()
        detected_at = data.get("detected_at") or now
        instruction_id = data.get("instruction_id")
        if instruction_id is None:
            instruction_id = self.instruction_repo.find_default_id(incident_type)

        incident = Incident(
            title=title,
            description=description,
            incident_type=incident_type,
            severity=severity,
            status=IncidentStatus.NEW.value,
            computer=str(data.get("computer") or ""),
            employee=str(data.get("employee") or ""),
            source=source,
            incident_key=str(data.get("incident_key") or ""),
            has_personal_data=has_pd,
            instruction_id=instruction_id,
            detected_at=detected_at,
            created_at=now,
            updated_at=now,
        )
        created = self.incident_repo.create(incident)
        self.history_repo.add(
            incident_id=created.id,
            user_id=actor.id,
            action="create",
            details=f"Создан инцидент: {created.title}",
            created_at=now,
        )
        self.access_control.log_access(actor.id, "incident", created.id, "create")
        if self.telegram_service is not None:
            self.telegram_service.notify_incident_created(created)
        return created.to_dict()


class IncidentService:
    """Application service for incident queries, updates, lifecycle, and classification."""

    def __init__(
        self,
        incident_repo: IncidentRepository,
        message_repo: MessageRepository,
        history_repo: HistoryRepository,
        instruction_repo: InstructionRepository,
        task_repo: TaskRepository,
        access_control: AccessControlService,
        ingestion_service: IngestionService,
        user_repo: UserRepository | None = None,
        telegram_service: "TelegramNotificationService | None" = None,
    ) -> None:
        self.incident_repo = incident_repo
        self.message_repo = message_repo
        self.history_repo = history_repo
        self.instruction_repo = instruction_repo
        self.task_repo = task_repo
        self.access_control = access_control
        self.ingestion_service = ingestion_service
        self.user_repo = user_repo or UserRepository(task_repo.db)
        self.telegram_service = telegram_service

    def list_incidents(
        self,
        user: User | Mapping[str, Any],
        q: str | None = None,
        incident_type: str | None = None,
        status: str | None = None,
        sort_by: str | None = DEFAULT_INCIDENT_SORT_BY,
        sort_order: str | None = DEFAULT_INCIDENT_SORT_ORDER,
    ) -> list[dict[str, Any]]:
        """List incidents visible to the current user."""
        actor = coerce_user(user)
        try:
            norm_sort_by, norm_sort_order = resolve_incident_sort(sort_by, sort_order)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

        incidents = self.incident_repo.list_filtered(
            q=q,
            incident_type=incident_type,
            status=status,
            exclude_personal_data=not self.access_control.can_view_pdn(actor),
            sort_by=norm_sort_by,
            sort_order=norm_sort_order,
        )
        return [
            inc.to_dict()
            for inc in incidents
            if self.access_control.can_view(actor, inc)
        ]

    def get_incident(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
    ) -> dict[str, Any]:
        """Return full incident card details including messages, history, steps, and tasks."""
        actor = coerce_user(user)
        incident = self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_access(actor, incident)
        self.access_control.log_access(actor.id, "incident", incident_id, "view")

        data = incident.to_dict()
        data["messages"] = [m.to_dict() for m in self.message_repo.list_by_incident(incident_id)]
        data["history"] = [h.to_dict() for h in self.history_repo.list_by_incident(incident_id)]
        # Frontend IncidentDetailPage checks `sp.completed === 1` on card step_progress items.
        data["step_progress"] = [
            {
                "incident_id": p.incident_id,
                "step_index": p.step_index,
                "completed": 1 if p.completed else 0,
                "updated_by": p.updated_by,
                "updated_at": p.updated_at,
            }
            for p in self.instruction_repo.list_progress(incident_id)
        ]
        data["tasks"] = enrich_tasks_with_users(
            self.task_repo.list_by_incident(incident_id),
            self.user_repo,
        )
        return data

    def create_incident(
        self,
        user: User | Mapping[str, Any],
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Delegate manual incident creation to IngestionService."""
        return self.ingestion_service.register_manually(data, user)

    def update_incident(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update editable fields on an incident and record history."""
        actor = coerce_user(user)
        incident = self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise NotFoundError("Инцидент не найден")
        self.access_control.assert_incident_fields_editable(actor, incident, data.keys())

        changed_fields: list[str] = []
        if data.get("title") is not None:
            incident.title = str(data["title"])
            changed_fields.append("title")
        if data.get("description") is not None:
            incident.description = str(data["description"])
            changed_fields.append("description")
        if data.get("incident_type") is not None:
            incident.incident_type = IncidentType.normalize(data["incident_type"]).value
            changed_fields.append("incident_type")
        if data.get("severity") is not None:
            incident.severity = Severity.normalize(data["severity"]).value
            changed_fields.append("severity")
        if "has_personal_data" in data and data["has_personal_data"] is not None:
            pdn = PdnFlag.from_bool_int(data["has_personal_data"]).to_bool_int()
            if pdn and not self.access_control.can_mark_pdn(actor):
                self.access_control.log_access(actor.id, "incident", incident_id, "edit_denied")
                raise AccessDeniedError("Доступ к инцидентам с ПДн запрещен")
            incident.has_personal_data = pdn
            incident.refresh_access_category()
            changed_fields.append("has_personal_data")
        if "instruction_id" in data:
            incident.instruction_id = data["instruction_id"]
            changed_fields.append("instruction_id")
        if data.get("rkn_draft") is not None:
            incident.rkn_draft = str(data["rkn_draft"])
            changed_fields.append("rkn_draft")
        if data.get("computer") is not None:
            incident.computer = str(data["computer"])
            changed_fields.append("computer")
        if data.get("employee") is not None:
            incident.employee = str(data["employee"])
            incident.refresh_access_category()
            changed_fields.append("employee")
        if "assigned_to" in data:
            incident.assign(data["assigned_to"])
            changed_fields.append("assigned_to")

        if changed_fields:
            now = utc_now()
            incident.updated_at = now
            updated = self.incident_repo.update(incident)
            self.history_repo.add(
                incident_id=incident_id,
                user_id=actor.id,
                action="update",
                details="Обновлены поля: " + ", ".join(changed_fields),
                created_at=now,
            )
            self.access_control.log_access(actor.id, "incident", incident_id, "update")
            return updated.to_dict()

        return incident.to_dict()

    def change_status(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
        status: IncidentStatus | str,
        outcome: str | None = None,
    ) -> dict[str, Any]:
        """Transition incident lifecycle status using domain aggregate methods."""
        actor = coerce_user(user)
        incident = self.incident_repo.get_by_id(incident_id)
        self.access_control.assert_operational_incident_access(
            actor,
            incident,
            object_type="incident",
            object_id=incident_id,
            detail="Изменение статуса инцидента запрещено",
        )
        if incident is None:
            raise NotFoundError("Инцидент не найден")

        old_status = incident.status
        try:
            target_status = IncidentStatus.normalize(status)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        normalized_outcome = normalize_outcome(outcome)
        now = utc_now()

        if target_status is IncidentStatus.IN_PROGRESS:
            if old_status in (IncidentStatus.IN_REVIEW.value, IncidentStatus.CLOSED.value):
                incident.return_to_work(normalized_outcome or "", now)
            else:
                incident.take(actor.id, now)
            if normalized_outcome is not None:
                incident.outcome = normalized_outcome
        elif target_status is IncidentStatus.IN_REVIEW:
            incident.send_to_review(now)
            if normalized_outcome is not None:
                incident.outcome = normalized_outcome
        elif target_status is IncidentStatus.CLOSED:
            final_outcome = (
                normalized_outcome if normalized_outcome is not None else incident.outcome
            )
            final_outcome = require_non_blank(final_outcome, "outcome")
            incident.close(final_outcome, now)
        else:
            incident.status = IncidentStatus.NEW.value
            incident.updated_at = now
            if normalized_outcome is not None:
                incident.outcome = normalized_outcome

        updated = self.incident_repo.update(incident)
        details = f"{old_status} -> {target_status.value}"
        if updated.outcome:
            details += f" ({updated.outcome})"
        self.history_repo.add(
            incident_id=incident_id,
            user_id=actor.id,
            action="status_change",
            details=details,
            created_at=now,
        )
        self.access_control.log_access(actor.id, "incident", incident_id, "status_change")
        if self.telegram_service is not None:
            self.telegram_service.notify_status_changed(updated, old_status, actor=actor)
        return updated.to_dict()

    def classify(
        self,
        user: User | Mapping[str, Any],
        incident_id: int,
        incident_type: IncidentType | str,
        severity: Severity | str,
    ) -> dict[str, Any]:
        """Assign normalized incident type and severity classification."""
        actor = coerce_user(user)
        incident = self.incident_repo.get_by_id(incident_id)
        self.access_control.assert_operational_incident_access(
            actor,
            incident,
            object_type="incident",
            object_id=incident_id,
            detail="Классификация инцидента запрещена",
        )
        if incident is None:
            raise NotFoundError("Инцидент не найден")

        norm_type = IncidentType.normalize(incident_type).value
        norm_sev = Severity.normalize(severity).value
        now = utc_now()

        incident.incident_type = norm_type
        incident.severity = norm_sev
        if incident.instruction_id is None:
            incident.instruction_id = self.instruction_repo.find_default_id(norm_type)
        incident.updated_at = now

        updated = self.incident_repo.update(incident)
        self.history_repo.add(
            incident_id=incident_id,
            user_id=actor.id,
            action="classify",
            details=f"Классификация: {norm_type}, важность: {norm_sev}",
            created_at=now,
        )
        self.access_control.log_access(actor.id, "incident", incident_id, "classify")
        return updated.to_dict()
