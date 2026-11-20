from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Any

from app.enums import AccessCategory, IncidentType, PdnFlag, Role, Severity


@dataclass(frozen=True)
class DispatchRule:
    """Routing, classification, and notification dispatch rule for an incident type."""

    incident_type: IncidentType
    default_severity: Severity
    access_category: AccessCategory
    responsible_role: Role
    urgent_notify_roles: tuple[Role, ...] = ()
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize dispatch rule fields to a plain JSON-ready dictionary."""
        return {
            "incident_type": self.incident_type.value,
            "incident_type_key": self.incident_type.name,
            "default_severity": self.default_severity.value,
            "access_category": self.access_category.value,
            "responsible_role": self.responsible_role.value,
            "responsible_role_label": self.responsible_role.label,
            "urgent_notify_roles": [role.value for role in self.urgent_notify_roles],
            "description": self.description,
        }


DEFAULT_DISPATCH_RULES: dict[IncidentType, DispatchRule] = {
    IncidentType.CVE: DispatchRule(
        incident_type=IncidentType.CVE,
        default_severity=Severity.HIGH,
        access_category=AccessCategory.TECHNICAL,
        responsible_role=Role.SYS_ADMIN,
        urgent_notify_roles=(),
        description="Уязвимость ПО или ОС (CVE): оценка критичности и установка обновлений.",
    ),
    IncidentType.BRUTEFORCE: DispatchRule(
        incident_type=IncidentType.BRUTEFORCE,
        default_severity=Severity.HIGH,
        access_category=AccessCategory.TECHNICAL,
        responsible_role=Role.SYS_ADMIN,
        urgent_notify_roles=(),
        description="Подбор паролей (SSH/RDP/AD): блокировка источника и аудит попыток входа.",
    ),
    IncidentType.VIRUS: DispatchRule(
        incident_type=IncidentType.VIRUS,
        default_severity=Severity.HIGH,
        access_category=AccessCategory.TECHNICAL,
        responsible_role=Role.SYS_ADMIN,
        urgent_notify_roles=(),
        description="Вредоносное ПО или вирус: изоляция рабочего места и антивирусная очистка.",
    ),
    IncidentType.PHISHING: DispatchRule(
        incident_type=IncidentType.PHISHING,
        default_severity=Severity.MEDIUM,
        access_category=AccessCategory.EMPLOYEE_INVOLVED,
        responsible_role=Role.SECURITY_SPECIALIST,
        urgent_notify_roles=(),
        description="Фишинговое письмо или ссылка: блокировка отправителя и сброс паролей.",
    ),
    IncidentType.DATA_LEAK: DispatchRule(
        incident_type=IncidentType.DATA_LEAK,
        default_severity=Severity.CRITICAL,
        access_category=AccessCategory.PERSONAL_DATA,
        responsible_role=Role.SECURITY_SPECIALIST,
        urgent_notify_roles=(Role.LAWYER,),
        description="Утечка персональных данных: локализация, правовая оценка и уведомление РКН (24/72ч).",
    ),
    IncidentType.PAYMENT_FRAUD: DispatchRule(
        incident_type=IncidentType.PAYMENT_FRAUD,
        default_severity=Severity.HIGH,
        access_category=AccessCategory.EMPLOYEE_INVOLVED,
        responsible_role=Role.SECURITY_SPECIALIST,
        urgent_notify_roles=(Role.ACCOUNTANT,),
        description="Подмена реквизитов или финансовое мошенничество: срочное оповещение главбуха.",
    ),
    IncidentType.UNAUTHORIZED_ACCESS: DispatchRule(
        incident_type=IncidentType.UNAUTHORIZED_ACCESS,
        default_severity=Severity.HIGH,
        access_category=AccessCategory.TECHNICAL,
        responsible_role=Role.SECURITY_SPECIALIST,
        urgent_notify_roles=(),
        description="Несанкционированный доступ или повышение привилегий: блокировка сессий и аудит.",
    ),
    IncidentType.OTHER: DispatchRule(
        incident_type=IncidentType.OTHER,
        default_severity=Severity.MEDIUM,
        access_category=AccessCategory.TECHNICAL,
        responsible_role=Role.IT_HEAD,
        urgent_notify_roles=(),
        description="Прочий инцидент или технологический сбой: первичная оценка руководителем ИТ.",
    ),
}


_TEXT_CLASSIFICATION_PATTERNS: tuple[tuple[IncidentType, re.Pattern[str]], ...] = (
    (
        IncidentType.CVE,
        re.compile(r"cve-\d{4}-\d+|уязвим|vulnerab", re.IGNORECASE),
    ),
    (
        IncidentType.BRUTEFORCE,
        re.compile(
            r"brute[ _-]?force|подбор парол|failed[ _-]?login|(?<![a-zа-я])rdp(?![a-zа-я])",
            re.IGNORECASE,
        ),
    ),
    (
        IncidentType.VIRUS,
        re.compile(
            r"trojan|ransom|malware|вирус|(?<![a-z])virus|заражен",
            re.IGNORECASE,
        ),
    ),
    (
        IncidentType.DATA_LEAK,
        re.compile(r"пдн|утечк|clients_pdn|data[ _-]?leak", re.IGNORECASE),
    ),
    (
        IncidentType.PAYMENT_FRAUD,
        re.compile(r"реквизит|платеж|(?<![a-zа-я])счет|payment", re.IGNORECASE),
    ),
    (
        IncidentType.PHISHING,
        re.compile(r"фишинг|phish", re.IGNORECASE),
    ),
    (
        IncidentType.UNAUTHORIZED_ACCESS,
        re.compile(
            r"несанкционирован|unauthori[sz]ed|privilege[ _-]?escalation",
            re.IGNORECASE,
        ),
    ),
)

_SOURCE_CLASSIFICATION_PATTERNS: tuple[tuple[IncidentType, tuple[str, ...]], ...] = (
    (IncidentType.VIRUS, ("antivirus", "kaspersky")),
    (IncidentType.DATA_LEAK, ("dlp",)),
)


def _prepare_text(raw: str | None) -> str:
    return (raw or "").strip().lower().replace("ё", "е")


def _match_text_patterns(text: str) -> IncidentType | None:
    if not text:
        return None
    for inc_type, pattern in _TEXT_CLASSIFICATION_PATTERNS:
        if pattern.search(text):
            return inc_type
    return None


class IncidentDispatcher:
    """OOP signal classifier and per-type incident dispatch rule resolver."""

    def __init__(self, rules: Mapping[IncidentType, DispatchRule] | None = None) -> None:
        merged = dict(DEFAULT_DISPATCH_RULES)
        if rules is not None:
            merged.update(rules)
        missing = [inc_type for inc_type in IncidentType if inc_type not in merged]
        if missing:
            raise ValueError(f"Missing dispatch rules for incident types: {missing}")
        self._rules: dict[IncidentType, DispatchRule] = merged

    def classify_signal(
        self,
        body: str,
        incident_type: str | None = None,
        source: str | None = None,
        error_code: str | None = None,
    ) -> IncidentType:
        """Classify an incoming signal by explicit type, error_code, body, or source."""
        if incident_type is not None and str(incident_type).strip():
            resolved = IncidentType.resolve(str(incident_type))
            if resolved is not None and resolved is not IncidentType.OTHER:
                return resolved

        cleaned_code = _prepare_text(error_code)
        if cleaned_code:
            resolved_code = IncidentType.resolve(cleaned_code)
            if resolved_code is not None and resolved_code is not IncidentType.OTHER:
                return resolved_code
            matched_code = _match_text_patterns(cleaned_code)
            if matched_code is not None:
                return matched_code

        matched_body = _match_text_patterns(_prepare_text(body))
        if matched_body is not None:
            return matched_body

        cleaned_source = _prepare_text(source)
        if cleaned_source:
            for inc_type, markers in _SOURCE_CLASSIFICATION_PATTERNS:
                if any(marker in cleaned_source for marker in markers):
                    return inc_type

        return IncidentType.OTHER

    def get_rule(self, incident_type: IncidentType | str) -> DispatchRule:
        """Return the DispatchRule configured for the given incident type."""
        norm_type = IncidentType.normalize(incident_type)
        return self._rules[norm_type]

    def list_rules(self) -> list[DispatchRule]:
        """Return all dispatch rules ordered by IncidentType enum definition."""
        return [self._rules[inc_type] for inc_type in IncidentType]

    def list_rules_serialized(self) -> list[dict[str, Any]]:
        """Return all dispatch rules serialized for API responses."""
        return [rule.to_dict() for rule in self.list_rules()]

    def resolve_access_category(
        self,
        incident_type: IncidentType | str,
        *,
        has_personal_data: int | bool = 0,
        employee: str = "",
    ) -> AccessCategory:
        """Compute effective AccessCategory from dispatch rule and incident attributes."""
        rule = self.get_rule(incident_type)
        if (
            PdnFlag.from_bool_int(has_personal_data) is PdnFlag.YES
            or rule.access_category is AccessCategory.PERSONAL_DATA
        ):
            return AccessCategory.PERSONAL_DATA
        if str(employee or "").strip() or rule.access_category is AccessCategory.EMPLOYEE_INVOLVED:
            return AccessCategory.EMPLOYEE_INVOLVED
        return rule.access_category

    def resolve_responsible_role(self, incident_type: IncidentType | str) -> Role:
        """Return the default responsible role for the given incident type."""
        return self.get_rule(incident_type).responsible_role

    def resolve_urgent_roles(
        self,
        incident_type: IncidentType | str,
        severity: Severity | str | None = None,
    ) -> tuple[Role, ...]:
        """Return deduplicated roles requiring immediate urgent notifications."""
        rule = self.get_rule(incident_type)
        roles: list[Role] = list(rule.urgent_notify_roles)

        effective_severity = rule.default_severity
        if severity is not None and str(severity).strip():
            try:
                effective_severity = Severity.normalize(str(severity))
            except ValueError:
                effective_severity = rule.default_severity

        if effective_severity is Severity.CRITICAL and Role.DIRECTOR not in roles:
            roles.append(Role.DIRECTOR)

        return tuple(roles)
