from collections.abc import Mapping
from typing import Any

from app.domain.models import Incident, User
from app.enums import AccessCategory, PdnFlag, Role
from app.repositories.sqlite_repo import AuditRepository
from app.services.exceptions import AccessDeniedError, coerce_user

_PDN_VIEW_ROLES: frozenset[Role] = frozenset(
    {
        Role.SECURITY_SPECIALIST,
        Role.IT_HEAD,
        Role.LAWYER,
        Role.DIRECTOR,
        Role.ACCOUNTANT,
    }
)

_EMPLOYEE_INCIDENT_VIEW_ROLES: frozenset[Role] = frozenset(
    {
        Role.SECURITY_SPECIALIST,
        Role.SYS_ADMIN,
        Role.IT_HEAD,
        Role.LAWYER,
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

_RKN_ACCESS_ROLES: frozenset[Role] = frozenset(
    {
        Role.SECURITY_SPECIALIST,
        Role.IT_HEAD,
        Role.LAWYER,
        Role.DIRECTOR,
        Role.ACCOUNTANT,
    }
)


def _incident_category(incident: Incident | Mapping[str, Any]) -> AccessCategory:
    if isinstance(incident, Incident):
        if PdnFlag.from_bool_int(incident.has_personal_data) is PdnFlag.YES:
            return AccessCategory.PERSONAL_DATA
        if incident.access_category:
            try:
                return AccessCategory(incident.access_category)
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

    def can_create_pdn(self, user: User | Mapping[str, Any]) -> bool:
        """Return True if the user is permitted to register or mark PDn incidents."""
        actor = coerce_user(user)
        return actor.active and actor.role in _PDN_VIEW_ROLES

    def can_access_rkn(self, user: User | Mapping[str, Any]) -> bool:
        """Return True if the user can view or edit Roskomnadzor notices."""
        actor = coerce_user(user)
        return actor.active and actor.role in _RKN_ACCESS_ROLES

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

    def assert_rkn_access(self, user: User | Mapping[str, Any]) -> None:
        """Verify RKN notice access or log denial and raise AccessDeniedError."""
        actor = coerce_user(user)
        if not self.can_access_rkn(actor):
            self.log_access(actor.id, "regulator_notice", None, "access_denied")
            raise AccessDeniedError("Доступ к данным РКН запрещен")

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
