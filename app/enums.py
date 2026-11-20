from enum import StrEnum


class Role(StrEnum):
    """User roles supported by the IS incident management system."""

    SECURITY_SPECIALIST = "ib_specialist"
    SYS_ADMIN = "sysadmin"
    IT_HEAD = "it_head"
    LAWYER = "lawyer"
    DIRECTOR = "director"
    ACCOUNTANT = "chief_accountant"
    FOREMAN = "foreman"
    EMPLOYEE = "employee"

    @property
    def label(self) -> str:
        """Return the Russian display title for this role."""
        return ROLE_LABELS[self]


ROLE_LABELS: dict[Role, str] = {
    Role.SECURITY_SPECIALIST: "Специалист ИБ",
    Role.SYS_ADMIN: "Системный администратор",
    Role.IT_HEAD: "Руководитель ИТ",
    Role.LAWYER: "Юрист",
    Role.DIRECTOR: "Директор",
    Role.ACCOUNTANT: "Главный бухгалтер",
    Role.FOREMAN: "Прораб",
    Role.EMPLOYEE: "Сотрудник",
}


def _clean_key(raw: str) -> str:
    return " ".join(raw.strip().lower().replace("-", "_").split())


class IncidentType(StrEnum):
    """Supported cybersecurity incident categories."""

    PHISHING = "Фишинг"
    VIRUS = "Вирус / Вредоносное ПО"
    BRUTEFORCE = "Подбор пароля"
    DATA_LEAK = "Утечка ПДн"
    PAYMENT_FRAUD = "Обман с платежами"
    UNAUTHORIZED_ACCESS = "Несанкционированный доступ"
    CVE = "Уязвимость (CVE)"
    OTHER = "Прочее"

    @classmethod
    def resolve(cls, raw: str | None) -> "IncidentType | None":
        """Match an enum value, member name, or known alias without fallback."""
        if isinstance(raw, cls):
            return raw
        if not isinstance(raw, str) or not raw.strip():
            return None

        stripped = raw.strip()
        lowered = stripped.lower()
        for member in cls:
            if lowered == member.value.lower() or stripped.upper() == member.name:
                return member

        key = _clean_key(stripped)
        return _INCIDENT_TYPE_ALIASES.get(key) or _INCIDENT_TYPE_ALIASES.get(key.replace(" ", "_"))

    @classmethod
    def normalize(cls, raw: str | None) -> "IncidentType":
        """Normalize an incident type or alias, falling back to OTHER."""
        return cls.resolve(raw) or cls.OTHER


_INCIDENT_TYPE_ALIASES: dict[str, IncidentType] = {
    "phishing": IncidentType.PHISHING,
    "фишинг": IncidentType.PHISHING,
    "virus": IncidentType.VIRUS,
    "malware": IncidentType.VIRUS,
    "trojan": IncidentType.VIRUS,
    "ransomware": IncidentType.VIRUS,
    "вирус": IncidentType.VIRUS,
    "вредоносное_по": IncidentType.VIRUS,
    "вирус_/_вредоносное_по": IncidentType.VIRUS,
    "bruteforce": IncidentType.BRUTEFORCE,
    "brute_force": IncidentType.BRUTEFORCE,
    "password_bruteforce": IncidentType.BRUTEFORCE,
    "подбор_пароля": IncidentType.BRUTEFORCE,
    "брутфорс": IncidentType.BRUTEFORCE,
    "data_leak": IncidentType.DATA_LEAK,
    "dataleak": IncidentType.DATA_LEAK,
    "pdn": IncidentType.DATA_LEAK,
    "pdn_leak": IncidentType.DATA_LEAK,
    "leak": IncidentType.DATA_LEAK,
    "утечка": IncidentType.DATA_LEAK,
    "утечка_пдн": IncidentType.DATA_LEAK,
    "payment_fraud": IncidentType.PAYMENT_FRAUD,
    "fraud": IncidentType.PAYMENT_FRAUD,
    "обман_с_платежами": IncidentType.PAYMENT_FRAUD,
    "платежное_мошенничество": IncidentType.PAYMENT_FRAUD,
    "unauthorized_access": IncidentType.UNAUTHORIZED_ACCESS,
    "unauth_access": IncidentType.UNAUTHORIZED_ACCESS,
    "unauthorized": IncidentType.UNAUTHORIZED_ACCESS,
    "nsd": IncidentType.UNAUTHORIZED_ACCESS,
    "нсд": IncidentType.UNAUTHORIZED_ACCESS,
    "несанкционированный_доступ": IncidentType.UNAUTHORIZED_ACCESS,
    "cve": IncidentType.CVE,
    "vulnerability": IncidentType.CVE,
    "vuln": IncidentType.CVE,
    "уязвимость": IncidentType.CVE,
    "уязвимость_(cve)": IncidentType.CVE,
    "other": IncidentType.OTHER,
    "прочее": IncidentType.OTHER,
}


class Severity(StrEnum):
    """Incident severity levels with numeric weights and Russian labels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        """Return numeric priority weight (1..4)."""
        return SEVERITY_WEIGHTS[self]

    @property
    def label(self) -> str:
        """Return the Russian display title for this severity level."""
        return SEVERITY_LABELS[self]

    @classmethod
    def normalize(cls, raw: str) -> "Severity":
        """Parse a severity value or English/Russian alias."""
        if isinstance(raw, cls):
            return raw
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError(f"Unknown severity: {raw!r}")

        key = _clean_key(raw)
        if key in _SEVERITY_ALIASES:
            return _SEVERITY_ALIASES[key]
        raise ValueError(f"Unknown severity: {raw!r}")


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

SEVERITY_LABELS: dict[Severity, str] = {
    Severity.LOW: "Низкий",
    Severity.MEDIUM: "Средний",
    Severity.HIGH: "Высокий",
    Severity.CRITICAL: "Критический",
}

_SEVERITY_ALIASES: dict[str, Severity] = {
    "low": Severity.LOW,
    "низкий": Severity.LOW,
    "низкая": Severity.LOW,
    "medium": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "средний": Severity.MEDIUM,
    "средняя": Severity.MEDIUM,
    "high": Severity.HIGH,
    "высокий": Severity.HIGH,
    "высокая": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "критический": Severity.CRITICAL,
    "критическая": Severity.CRITICAL,
    "критичный": Severity.CRITICAL,
    "критичная": Severity.CRITICAL,
}


class IncidentStatus(StrEnum):
    """Lifecycle states of an incident."""

    NEW = "Новый"
    IN_PROGRESS = "В работе"
    IN_REVIEW = "На проверке"
    CLOSED = "Закрыт"

    @classmethod
    def resolve(cls, raw: str | None) -> "IncidentStatus | None":
        """Match an incident status value, member name, or alias."""
        if isinstance(raw, cls):
            return raw
        if not isinstance(raw, str) or not raw.strip():
            return None

        stripped = raw.strip()
        lowered = stripped.lower()
        for member in cls:
            if lowered == member.value.lower() or stripped.upper() == member.name:
                return member

        key = _clean_key(stripped).replace(" ", "_")
        return _INCIDENT_STATUS_ALIASES.get(key)

    @classmethod
    def normalize(cls, raw: str) -> "IncidentStatus":
        """Normalize an incident status or raise ValueError."""
        resolved = cls.resolve(raw)
        if resolved is None:
            raise ValueError(f"Unknown incident status: {raw!r}")
        return resolved


_INCIDENT_STATUS_ALIASES: dict[str, IncidentStatus] = {
    "new": IncidentStatus.NEW,
    "новый": IncidentStatus.NEW,
    "in_progress": IncidentStatus.IN_PROGRESS,
    "progress": IncidentStatus.IN_PROGRESS,
    "в_работе": IncidentStatus.IN_PROGRESS,
    "in_review": IncidentStatus.IN_REVIEW,
    "review": IncidentStatus.IN_REVIEW,
    "на_проверке": IncidentStatus.IN_REVIEW,
    "closed": IncidentStatus.CLOSED,
    "close": IncidentStatus.CLOSED,
    "закрыт": IncidentStatus.CLOSED,
}


class CheckResult(StrEnum):
    """Incident verification / resolution outcomes."""

    CONFIRMED = "Инцидент подтверждён"
    RESOLVED = "Устранен"
    FALSE_POSITIVE = "Ложное срабатывание"
    NOT_CONFIRMED = "Не удалось подтвердить"

    @classmethod
    def normalize(cls, raw: str) -> "CheckResult":
        """Normalize a check result value or alias, or raise ValueError."""
        if isinstance(raw, cls):
            return raw
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError(f"Unknown check result: {raw!r}")

        stripped = raw.strip()
        lowered = stripped.lower()
        for member in cls:
            if lowered == member.value.lower() or stripped.upper() == member.name:
                return member

        key = _clean_key(stripped).replace(" ", "_")
        if key in _CHECK_RESULT_ALIASES:
            return _CHECK_RESULT_ALIASES[key]
        raise ValueError(f"Unknown check result: {raw!r}")


_CHECK_RESULT_ALIASES: dict[str, CheckResult] = {
    "confirmed": CheckResult.CONFIRMED,
    "инцидент_подтверждён": CheckResult.CONFIRMED,
    "инцидент_подтвержден": CheckResult.CONFIRMED,
    "resolved": CheckResult.RESOLVED,
    "устранен": CheckResult.RESOLVED,
    "устранён": CheckResult.RESOLVED,
    "false_positive": CheckResult.FALSE_POSITIVE,
    "ложное_срабатывание": CheckResult.FALSE_POSITIVE,
    "not_confirmed": CheckResult.NOT_CONFIRMED,
    "не_удалось_подтвердить": CheckResult.NOT_CONFIRMED,
}


class PdnFlag(StrEnum):
    """Personal data involvement flag."""

    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"

    @classmethod
    def from_bool_int(cls, val: "bool | int | PdnFlag | None") -> "PdnFlag":
        """Convert bool, 0/1 int, or None into a PdnFlag."""
        if val is None:
            return cls.UNKNOWN
        if isinstance(val, cls):
            return val
        if isinstance(val, bool):
            return cls.YES if val else cls.NO
        if isinstance(val, int):
            return cls.YES if val else cls.NO
        raise ValueError(f"Cannot convert {val!r} to {cls.__name__}")

    def to_bool_int(self) -> int:
        """Convert to SQLite integer flag (1 for YES, 0 otherwise)."""
        return 1 if self is PdnFlag.YES else 0


class AccessCategory(StrEnum):
    """Access-control categories for incidents."""

    TECHNICAL = "technical"
    PERSONAL_DATA = "personal_data"
    EMPLOYEE_INVOLVED = "employee_involved"


class SourceType(StrEnum):
    """Signal and incident ingestion sources."""

    KASPERSKY = "antivirus"
    ZABBIX = "zabbix"
    DLP = "dlp"
    EMAIL = "mail_gateway"
    TELEGRAM = "telegram"
    MANUAL = "manual"

    @classmethod
    def normalize(cls, raw: str | None) -> "SourceType":
        """Normalize a source identifier or alias, falling back to MANUAL."""
        if isinstance(raw, cls):
            return raw
        if not isinstance(raw, str) or not raw.strip():
            return cls.MANUAL

        stripped = raw.strip()
        lowered = stripped.lower()
        for member in cls:
            if lowered == member.value.lower() or stripped.upper() == member.name:
                return member

        key = _clean_key(stripped).replace(" ", "_")
        return _SOURCE_TYPE_ALIASES.get(key, cls.MANUAL)


_SOURCE_TYPE_ALIASES: dict[str, SourceType] = {
    "antivirus": SourceType.KASPERSKY,
    "kaspersky": SourceType.KASPERSKY,
    "kaspersky_endpoint_security": SourceType.KASPERSKY,
    "ksc": SourceType.KASPERSKY,
    "av": SourceType.KASPERSKY,
    "zabbix": SourceType.ZABBIX,
    "dlp": SourceType.DLP,
    "mail_gateway": SourceType.EMAIL,
    "email": SourceType.EMAIL,
    "mail": SourceType.EMAIL,
    "почта": SourceType.EMAIL,
    "telegram": SourceType.TELEGRAM,
    "tg": SourceType.TELEGRAM,
    "телеграм": SourceType.TELEGRAM,
    "manual": SourceType.MANUAL,
    "ручной": SourceType.MANUAL,
}


class TaskStatus(StrEnum):
    """Task execution states."""

    OPEN = "Открыта"
    DONE = "Выполнена"
    OVERDUE = "Просрочена"

    @classmethod
    def is_done(cls, status: "TaskStatus | str | None") -> bool:
        """Return True if the task status denotes completion."""
        return str(status or "").strip().lower() in DONE_TASK_STATUSES

    @classmethod
    def resolve(cls, raw: str | None) -> "TaskStatus | None":
        """Match a task status value, member name, or known completion alias."""
        if isinstance(raw, cls):
            return raw
        if not isinstance(raw, str) or not raw.strip():
            return None

        stripped = raw.strip()
        lowered = stripped.lower()
        for member in cls:
            if lowered == member.value.lower() or stripped.upper() == member.name:
                return member
        if lowered in DONE_TASK_STATUSES:
            return cls.DONE
        return _TASK_STATUS_ALIASES.get(_clean_key(stripped))

    @classmethod
    def normalize(cls, raw: str) -> "TaskStatus":
        """Normalize a task status or raise ValueError."""
        resolved = cls.resolve(raw)
        if resolved is None:
            raise ValueError(f"Unknown task status: {raw!r}")
        return resolved


DONE_TASK_STATUSES: frozenset[str] = frozenset(
    {
        TaskStatus.DONE.value.lower(),
        "завершена",
        "закрыта",
        "done",
    }
)

_TASK_STATUS_ALIASES: dict[str, TaskStatus] = {
    "open": TaskStatus.OPEN,
    "открыта": TaskStatus.OPEN,
    "done": TaskStatus.DONE,
    "overdue": TaskStatus.OVERDUE,
    "просрочена": TaskStatus.OVERDUE,
}


class Channel(StrEnum):
    """Notification delivery channels."""

    TELEGRAM = "telegram"
    EMAIL = "email"
    INTERNAL = "internal"


class DeliveryStatus(StrEnum):
    """Notification delivery outcome statuses."""

    SENT = "sent"
    FAILED = "failed"


class ReportFormat(StrEnum):
    """Supported report export formats."""

    PDF = "pdf"
    WORD = "word"
    JSON = "json"
