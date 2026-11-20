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
