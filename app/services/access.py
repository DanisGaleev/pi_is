from collections.abc import Iterable, Mapping
from typing import Any

from app.domain.models import Incident, User
from app.enums import AccessCategory, PdnFlag, Role
from app.repositories.sqlite_repo import AuditRepository
from app.services.exceptions import AccessDeniedError, coerce_user

LAWYER_EDITABLE_FIELDS: frozenset[str] = frozenset({"rkn_draft", "has_personal_data"})

_PDN_VIEW_ROLES: frozenset[Role] = frozenset(
    {
        Role.SECURITY_SPECIALIST,
        Role.IT_HEAD,
        Role.LAWYER,
        Role.DIRECTOR,
        Role.ACCOUNTANT,
    }
)

_PDN_CREATE_ROLES: frozenset[Role] = frozenset(
    {
        Role.SECURITY_SPECIALIST,
        Role.IT_HEAD,
        Role.DIRECTOR,
        Role.ACCOUNTANT,
    }
)

_PDN_MARK_ROLES: frozenset[Role] = frozenset(
    {
        Role.SECURITY_SPECIALIST,
        Role.IT_HEAD,
        Role.LAWYER,
    }
)

_EMPLOYEE_INCIDENT_VIEW_ROLES: frozenset[Role] = frozenset(
    {
        Role.SECURITY_SPECIALIST,
        Role.SYS_ADMIN,
        Role.IT_HEAD,
        Role.DIRECTOR,
        Role.ACCOUNTANT,
        Role.FOREMAN,
    }
)

_EDIT_ROLES: frozenset[Role] = frozenset(
    {
        Role.SECURITY_SPECIALIST,
        Role.SYS_ADMIN,
        Role.IT_HEAD,
        Role.LAWYER,
    }
)

_OPERATIONAL_EDIT_ROLES: frozenset[Role] = frozenset(
    {
        Role.SECURITY_SPECIALIST,
        Role.SYS_ADMIN,
        Role.IT_HEAD,
    }
)

_RKN_ACCESS_ROLES: frozenset[Role] = frozenset(
    {
        Role.SECURITY_SPECIALIST,
        Role.IT_HEAD,
        Role.LAWYER,
        Role.DIRECTOR,
        Role.ACCOUNTANT,
    }
)

_TELEGRAM_MANAGE_ROLES: frozenset[Role] = frozenset(
    {
        Role.SECURITY_SPECIALIST,
        Role.IT_HEAD,
    }
)


def _incident_category(incident: Incident | Mapping[str, Any]) -> AccessCategory:
    if isinstance(incident, Incident):
        if PdnFlag.from_bool_int(incident.has_personal_data) is PdnFlag.YES:
            return AccessCategory.PERSONAL_DATA
        if incident.access_category:
            try:
                cat = AccessCategory(incident.access_category)
                if cat is not AccessCategory.PERSONAL_DATA:
                    return cat
            except ValueError:
                pass
        return incident.resolve_access_category()

    if PdnFlag.from_bool_int(incident["has_personal_data"]) is PdnFlag.YES:
        return AccessCategory.PERSONAL_DATA
    if str(incident.get("employee") or "").strip():
        return AccessCategory.EMPLOYEE_INVOLVED
    return AccessCategory.TECHNICAL


def _incident_id(incident: Incident | Mapping[str, Any]) -> int | None:
    if isinstance(incident, Incident):
        return incident.id
    return incident.get("id")


class AccessControlService:
    """Role-based access control and security audit logging service."""

    def __init__(self, audit_repo: AuditRepository) -> None:
        self.audit_repo = audit_repo

    def can_view(
        self,
        user: User | Mapping[str, Any],
        incident: Incident | Mapping[str, Any],
    ) -> bool:
        """Return True if the user is allowed to view the incident."""
        actor = coerce_user(user)
        if not actor.active:
            return False

        category = _incident_category(incident)
        if category is AccessCategory.PERSONAL_DATA:
            return actor.role in _PDN_VIEW_ROLES
        if actor.role is Role.LAWYER:
            return False
        if category is AccessCategory.EMPLOYEE_INVOLVED:
            return actor.role in _EMPLOYEE_INCIDENT_VIEW_ROLES
        return True

    def can_edit(
        self,
        user: User | Mapping[str, Any],
        incident: Incident | Mapping[str, Any],
    ) -> bool:
        """Return True if the user can view and modify the incident."""
        actor = coerce_user(user)
        if not self.can_view(actor, incident):
            return False
        return actor.role in _EDIT_ROLES

    def can_view_pdn(self, user: User | Mapping[str, Any]) -> bool:
        """Return True if the user is allowed to view PDn incidents and related data."""
        actor = coerce_user(user)
        return actor.active and actor.role in _PDN_VIEW_ROLES

    def can_create_pdn(self, user: User | Mapping[str, Any]) -> bool:
        """Return True if the user is permitted to register PDn incidents."""
        actor = coerce_user(user)
        return actor.active and actor.role in _PDN_CREATE_ROLES

    def can_mark_pdn(self, user: User | Mapping[str, Any]) -> bool:
        """Return True if the user can mark an accessible incident as containing PDn."""
        actor = coerce_user(user)
        return actor.active and actor.role in _PDN_MARK_ROLES

    def can_create_incident(
        self,
        user: User | Mapping[str, Any],
        has_personal_data: bool = False,
    ) -> bool:
        """Return True if the user can manually register an incident."""
        actor = coerce_user(user)
        if not actor.active or actor.role is Role.LAWYER:
            return False
        if has_personal_data:
            return self.can_create_pdn(actor)
        return True

    def can_edit_operational(self, user: User | Mapping[str, Any]) -> bool:
        """Return True if the user may perform operational incident/task actions."""
        actor = coerce_user(user)
        return actor.active and actor.role in _OPERATIONAL_EDIT_ROLES

    def can_edit_incident_fields(
        self,
        user: User | Mapping[str, Any],
        incident: Incident | Mapping[str, Any],
        fields: Iterable[str],
    ) -> bool:
        """Return True if the user can update every requested field on the incident."""
        actor = coerce_user(user)
        if not self.can_edit(actor, incident):
            return False
        if actor.role is Role.LAWYER:
            return all(field in LAWYER_EDITABLE_FIELDS for field in fields)
        return True

    def can_access_tasks(self, user: User | Mapping[str, Any]) -> bool:
        """Return True if the user can list or view operational tasks."""
        actor = coerce_user(user)
        return actor.active and actor.role is not Role.LAWYER

    def can_access_rkn(self, user: User | Mapping[str, Any]) -> bool:
        """Return True if the user can view or edit Roskomnadzor notices."""
        actor = coerce_user(user)
        return actor.active and actor.role in _RKN_ACCESS_ROLES

    def can_manage_telegram(self, user: User | Mapping[str, Any]) -> bool:
        """Return True if the user can configure Telegram bot and manage subscriptions."""
        actor = coerce_user(user)
        return actor.active and actor.role in _TELEGRAM_MANAGE_ROLES

    def assert_telegram_manage_access(
        self,
        user: User | Mapping[str, Any],
        *,
        action: str = "access_denied",
    ) -> None:
        """Verify permission to manage Telegram notifications or log denial."""
        actor = coerce_user(user)
        if not self.can_manage_telegram(actor):
            self.log_access(actor.id, "telegram_config", None, action)
            raise AccessDeniedError("Управление Telegram-уведомлениями запрещено")

    def assert_incident_access(
        self,
        user: User | Mapping[str, Any],
        incident: Incident | Mapping[str, Any],
        *,
        edit: bool = False,
    ) -> None:
        """Verify incident access or log denial and raise AccessDeniedError."""
        actor = coerce_user(user)
        inc_id = _incident_id(incident)
        category = _incident_category(incident)

        if not self.can_view(actor, incident):
            self.log_access(actor.id, "incident", inc_id, "access_denied")
            detail = (
                "Доступ к инцидентам с ПДн запрещен"
                if category is AccessCategory.PERSONAL_DATA
                else "Доступ к инциденту запрещен"
            )
            raise AccessDeniedError(detail)

        if edit and not self.can_edit(actor, incident):
            self.log_access(actor.id, "incident", inc_id, "edit_denied")
            raise AccessDeniedError("Редактирование инцидента запрещено")

    def assert_incident_fields_editable(
        self,
        user: User | Mapping[str, Any],
        incident: Incident | Mapping[str, Any],
        fields: Iterable[str],
    ) -> None:
        """Verify base edit permission and field-level edit restrictions (e.g. lawyer)."""
        actor = coerce_user(user)
        self.assert_incident_access(actor, incident, edit=True)
        if actor.role is Role.LAWYER:
            disallowed = [field for field in fields if field not in LAWYER_EDITABLE_FIELDS]
            if disallowed:
                self.log_access(actor.id, "incident", _incident_id(incident), "edit_denied")
                raise AccessDeniedError(
                    "Юрист может изменять только правовые поля (rkn_draft, has_personal_data)"
                )

    def assert_create_incident_access(
        self,
        user: User | Mapping[str, Any],
        *,
        has_personal_data: bool = False,
    ) -> None:
        """Verify manual incident creation permission or log denial and raise AccessDeniedError."""
        actor = coerce_user(user)
        if not actor.active or actor.role is Role.LAWYER:
            self.log_access(actor.id, "incident", None, "create_denied")
            raise AccessDeniedError("Создание инцидентов запрещено")
        if has_personal_data and not self.can_create_pdn(actor):
            self.log_access(actor.id, "incident", None, "create_denied")
            raise AccessDeniedError("Доступ к инцидентам с ПДн запрещен")

    def assert_operational_access(
        self,
        user: User | Mapping[str, Any],
        object_type: str = "incident",
        object_id: int | None = None,
        *,
        action: str = "edit_denied",
        detail: str = "Операционное действие запрещено",
    ) -> None:
        """Verify operational role permission (status, steps, tasks, classification)."""
        actor = coerce_user(user)
        if not self.can_edit_operational(actor):
            self.log_access(actor.id, object_type, object_id, action)
            raise AccessDeniedError(detail)

    def assert_operational_incident_access(
        self,
        user: User | Mapping[str, Any],
        incident: Incident | Mapping[str, Any] | None,
        *,
        object_type: str = "incident",
        object_id: int | None = None,
        action: str = "edit_denied",
        detail: str = "Операционное действие запрещено",
    ) -> None:
        """Verify operational permission on an incident, checking role before 404 leaks."""
        actor = coerce_user(user)
        if incident is None:
            self.assert_operational_access(
                actor,
                object_type,
                object_id,
                action=action,
                detail=detail,
            )
            return
        self.assert_incident_access(actor, incident, edit=True)
        self.assert_operational_access(
            actor,
            object_type,
            object_id,
            action=action,
            detail=detail,
        )

    def assert_task_view_access(self, user: User | Mapping[str, Any]) -> None:
        """Verify permission to view operational task queues."""
        actor = coerce_user(user)
        if not self.can_access_tasks(actor):
            self.log_access(actor.id, "task", None, "access_denied")
            raise AccessDeniedError("Доступ к задачам запрещен")

    def assert_rkn_access(
        self,
        user: User | Mapping[str, Any],
        incident: Incident | Mapping[str, Any] | None = None,
    ) -> None:
        """Verify RKN notice access or log denial and raise AccessDeniedError."""
        actor = coerce_user(user)
        inc_id = _incident_id(incident) if incident is not None else None
        if not self.can_access_rkn(actor):
            self.log_access(actor.id, "regulator_notice", inc_id, "access_denied")
            raise AccessDeniedError("Доступ к данным РКН запрещен")
        if (
            incident is not None
            and actor.role is Role.LAWYER
            and _incident_category(incident) is not AccessCategory.PERSONAL_DATA
        ):
            self.log_access(actor.id, "regulator_notice", inc_id, "access_denied")
            raise AccessDeniedError("Доступ к уведомлениям РКН разрешен только по инцидентам с ПДн")

    def log_access(
        self,
        user_id: int | None,
        object_type: str,
        object_id: int | None,
        action: str,
    ) -> None:
        """Persist an access or mutation audit entry."""
        self.audit_repo.log(
            user_id=user_id,
            object_type=object_type,
            object_id=object_id,
            action=action,
        )
