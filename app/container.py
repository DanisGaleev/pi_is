from collections.abc import Callable

from app.enums import SourceType
from app.integration.adapters import (
    ADAPTER_REGISTRY,
    AuthProvider,
    DomainAuth,
    LocalAuth,
    SourceAdapter,
    TelegramAdapter,
)
from app.repositories.sqlite_repo import (
    AuditRepository,
    Database,
    HistoryRepository,
    IncidentRepository,
    IngestionErrorRepository,
    InstructionRepository,
    MessageRepository,
    NotificationRepository,
    SessionRepository,
    TaskRepository,
    UserRepository,
)
from app.services.access import AccessControlService
from app.services.dispatch import IncidentDispatcher
from app.services.incidents import (
    DeduplicationService,
    IncidentService,
    IngestionService,
)
from app.services.ops import (
    DeadlineService,
    EscalationService,
    InstructionService,
    NotificationService,
    ReportService,
    TaskService,
)
from app.services.users import UserService


class AppContainer:
    """Application composition root wiring DB, repositories, adapters, and services."""

    def __init__(
        self,
        db_path: str | None = None,
        *,
        domain_available: bool = False,
        ad_verifier: Callable[[str, str], bool] | None = None,
    ) -> None:
        self.db = Database(db_path)

        self.user_repo = UserRepository(self.db)
        self.session_repo = SessionRepository(self.db)
        self.incident_repo = IncidentRepository(self.db)
        self.message_repo = MessageRepository(self.db)
        self.history_repo = HistoryRepository(self.db)
        self.instruction_repo = InstructionRepository(self.db)
        self.task_repo = TaskRepository(self.db)
        self.notification_repo = NotificationRepository(self.db)
        self.audit_repo = AuditRepository(self.db)
        self.ingestion_error_repo = IngestionErrorRepository(self.db)

        self.adapters: dict[SourceType, SourceAdapter] = dict(ADAPTER_REGISTRY)
        self.local_auth = LocalAuth(self.user_repo)
        self.domain_auth = DomainAuth(
            self.local_auth,
            domain_available=domain_available,
            ad_verifier=ad_verifier,
        )
        self.auth_provider: AuthProvider = self.domain_auth

        self.access_service = AccessControlService(self.audit_repo)
        self.dispatcher = IncidentDispatcher()
        telegram = self.adapters.get(SourceType.TELEGRAM)
        self.notification_service = NotificationService(
            notification_repo=self.notification_repo,
            user_repo=self.user_repo,
            telegram_adapter=telegram if isinstance(telegram, TelegramAdapter) else None,
        )
        self.deduplication_service = DeduplicationService(
            incident_repo=self.incident_repo,
            message_repo=self.message_repo,
            history_repo=self.history_repo,
        )
        self.ingestion_service = IngestionService(
            incident_repo=self.incident_repo,
            message_repo=self.message_repo,
            history_repo=self.history_repo,
            instruction_repo=self.instruction_repo,
            ingestion_error_repo=self.ingestion_error_repo,
            deduplication_service=self.deduplication_service,
            access_control=self.access_service,
            adapters=self.adapters,
            dispatcher=self.dispatcher,
            user_repo=self.user_repo,
            notification_service=self.notification_service,
        )
        self.incident_service = IncidentService(
            incident_repo=self.incident_repo,
            message_repo=self.message_repo,
            history_repo=self.history_repo,
            instruction_repo=self.instruction_repo,
            task_repo=self.task_repo,
            access_control=self.access_service,
            ingestion_service=self.ingestion_service,
            user_repo=self.user_repo,
        )
        self.user_service = UserService(self.user_repo)
        self.instruction_service = InstructionService(
            incident_repo=self.incident_repo,
            instruction_repo=self.instruction_repo,
            history_repo=self.history_repo,
            access_control=self.access_service,
        )
        self.task_service = TaskService(
            task_repo=self.task_repo,
            incident_repo=self.incident_repo,
            user_repo=self.user_repo,
            history_repo=self.history_repo,
            access_control=self.access_service,
        )
        self.deadline_service = DeadlineService(
            incident_repo=self.incident_repo,
            history_repo=self.history_repo,
            access_control=self.access_service,
        )
        self.escalation_service = EscalationService(
            incident_repo=self.incident_repo,
            user_repo=self.user_repo,
            history_repo=self.history_repo,
            notification_service=self.notification_service,
            notification_repo=self.notification_repo,
        )
        self.report_service = ReportService(self.incident_repo, dispatcher=self.dispatcher)

    def init_db(self) -> None:
        """Initialize and migrate database schema for the active DB_PATH."""
        self.db.init_schema()


container = AppContainer()


def get_container() -> AppContainer:
    """Return the shared application container."""
    return container
