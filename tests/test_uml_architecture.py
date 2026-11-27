import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.container import AppContainer, get_container
from app.domain import (
    Attachment,
    AuditRecord,
    Computer,
    Deadlines,
    Department,
    FollowUpMeasure,
    HistoryRecord,
    Incident,
    IncomingMessage,
    IngestionError,
    Instruction,
    InstructionProgress,
    InstructionVersion,
    Notification,
    RegulatorNotice,
    ReportFile,
    Site,
    Task,
    User,
)
from app.enums import (
    AccessCategory,
    Channel,
    CheckResult,
    DeliveryStatus,
    IncidentStatus,
    IncidentType,
    ReportFormat,
    Role,
    Severity,
    SourceType,
    TaskStatus,
)
from app.integration import (
    ADAPTER_REGISTRY,
    AuthProvider,
    DomainAuth,
    KasperskyAdapter,
    LocalAuth,
    MailAdapter,
    SourceAdapter,
    TelegramAdapter,
    ZabbixAdapter,
)
from app.repositories import Database, hash_password
from app.services import (
    AccessControlService,
    AccessDeniedError,
    DeadlineService,
    DeduplicationService,
    EscalationService,
    IncidentService,
    IngestionService,
    InstructionService,
    NotFoundError,
    NotificationService,
    ReportService,
    TaskService,
    ValidationError,
)


class TestDomainModels(unittest.TestCase):
    def test_incident_lifecycle_and_access_category(self) -> None:
        inc = Incident(
            id=10,
            title="Подозрительный процесс",
            description="Запуск неизвестного бинарника",
            incident_type=IncidentType.VIRUS.value,
            severity=Severity.HIGH.value,
            computer="WS-01",
            employee="",
            has_personal_data=0,
            detected_at="2026-11-20T10:00:00+00:00",
        )
        self.assertEqual(inc.access_category, AccessCategory.TECHNICAL.value)

        inc.employee = "Иванов И.И."
        self.assertEqual(inc.refresh_access_category(), AccessCategory.EMPLOYEE_INVOLVED)
        self.assertEqual(inc.access_category, AccessCategory.EMPLOYEE_INVOLVED.value)

        inc.has_personal_data = 1
        self.assertEqual(inc.refresh_access_category(), AccessCategory.PERSONAL_DATA)

        inc.assign(42, "2026-11-20T10:05:00+00:00")
        self.assertEqual(inc.assigned_to, 42)
        self.assertEqual(inc.updated_at, "2026-11-20T10:05:00+00:00")

        inc.take(7, "2026-11-20T10:10:00+00:00")
        self.assertEqual(inc.status, IncidentStatus.IN_PROGRESS.value)
        self.assertEqual(inc.taken_at, "2026-11-20T10:10:00+00:00")
        self.assertEqual(inc.assigned_to, 7)

        # Subsequent take must preserve original taken_at timestamp.
        inc.take(8, "2026-11-20T10:20:00+00:00")
        self.assertEqual(inc.taken_at, "2026-11-20T10:10:00+00:00")
        self.assertEqual(inc.assigned_to, 8)

        inc.send_to_review("2026-11-20T11:00:00+00:00")
        self.assertEqual(inc.status, IncidentStatus.IN_REVIEW.value)
        self.assertEqual(inc.updated_at, "2026-11-20T11:00:00+00:00")

        inc.close(CheckResult.RESOLVED.value, "2026-11-20T12:00:00+00:00")
        self.assertEqual(inc.status, IncidentStatus.CLOSED.value)
        self.assertEqual(inc.outcome, CheckResult.RESOLVED.value)
        self.assertEqual(inc.closed_at, "2026-11-20T12:00:00+00:00")

        inc.return_to_work("Требуется доп. проверка", "2026-11-20T13:00:00+00:00")
        self.assertEqual(inc.status, IncidentStatus.IN_PROGRESS.value)
        self.assertIsNone(inc.closed_at)
        self.assertEqual(inc.updated_at, "2026-11-20T13:00:00+00:00")

        serialized = inc.to_dict()
        self.assertEqual(serialized["id"], 10)
        self.assertEqual(serialized["access_category"], AccessCategory.PERSONAL_DATA.value)
        self.assertEqual(serialized["assigned_to"], 8)

    def test_task_complete_and_is_overdue(self) -> None:
        now = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
        past_due = (now - timedelta(hours=2)).isoformat()
        future_due = (now + timedelta(hours=4)).isoformat()

        overdue_task = Task(
            id=1,
            incident_id=1,
            title="Проверить хост",
            description="Сканирование",
            assigned_to=2,
            status=TaskStatus.OPEN.value,
            result="",
            created_by=1,
            created_at="2026-11-20T08:00:00+00:00",
            due_date=past_due,
        )
        self.assertTrue(overdue_task.is_overdue(now))

        future_task = Task(
            id=2,
            incident_id=1,
            title="Собрать логи",
            description="",
            assigned_to=2,
            status=TaskStatus.OPEN.value,
            result="",
            created_by=1,
            created_at="2026-11-20T08:00:00+00:00",
            due_date=future_due,
        )
        self.assertFalse(future_task.is_overdue(now))

        status_overdue = Task(
            id=3,
            incident_id=1,
            title="Срочная задача",
            description="",
            assigned_to=2,
            status=TaskStatus.OVERDUE.value,
            result="",
            created_by=1,
            created_at="2026-11-20T08:00:00+00:00",
        )
        self.assertTrue(status_overdue.is_overdue(now))

        overdue_task.complete("Угроза удалена", "2026-11-20T12:05:00+00:00")
        self.assertEqual(overdue_task.status, TaskStatus.DONE.value)
        self.assertEqual(overdue_task.result, "Угроза удалена")
        self.assertEqual(overdue_task.completed_at, "2026-11-20T12:05:00+00:00")
        self.assertFalse(overdue_task.is_overdue(now))
        self.assertEqual(overdue_task.to_dict()["result"], "Угроза удалена")
        self.assertEqual(overdue_task.assignee_ids, [2])

        # Multi-assignee domain helpers (max 3, deduplication, primary sync)
        self.assertTrue(overdue_task.add_assignee(3))
        self.assertFalse(overdue_task.add_assignee(3))  # idempotent
        self.assertTrue(overdue_task.add_assignee(4))
        self.assertEqual(overdue_task.assignee_ids, [2, 3, 4])
        self.assertEqual(overdue_task.assigned_to, 2)
        with self.assertRaises(ValueError):
            overdue_task.add_assignee(5)

        self.assertTrue(overdue_task.remove_assignee(2))
        self.assertEqual(overdue_task.assignee_ids, [3, 4])
        self.assertEqual(overdue_task.assigned_to, 3)
        self.assertFalse(overdue_task.remove_assignee(999))

        overdue_task.set_assignees([5, 5, 6])
        self.assertEqual(overdue_task.assignee_ids, [5, 6])
        self.assertEqual(overdue_task.assigned_to, 5)
        with self.assertRaises(ValueError):
            overdue_task.set_assignees([1, 2, 3, 4])

    def test_regulator_notice_build_draft_and_mark_sent(self) -> None:
        inc = Incident(
            id=5,
            title="Утечка базы клиентов",
            description="Архив отправлен наружу",
            incident_type=IncidentType.DATA_LEAK.value,
            computer="SRV-CRM-01",
            employee="Волков И.П.",
            has_personal_data=1,
            detected_at="2026-11-20T09:00:00+00:00",
        )
        draft = RegulatorNotice.build_draft(
            inc,
            "2026-11-21T09:00:00+00:00",
            "2026-11-23T09:00:00+00:00",
        )
        self.assertIn("РОСКОМНАДЗОР", draft)
        self.assertIn("#5", draft)
        self.assertIn("Наличие ПДн: Да", draft)

        notice = RegulatorNotice(
            incident_id=5,
            detected_at=inc.detected_at,
            deadline_24h="2026-11-21T09:00:00+00:00",
            deadline_72h="2026-11-23T09:00:00+00:00",
            overdue_24h=False,
            overdue_72h=False,
            rkn_draft=draft,
            is_auto_generated=True,
        )
        notice.mark_sent("RKN-2026-001", "2026-11-20T11:30:00+00:00")
        self.assertEqual(notice.confirmation, "RKN-2026-001")
        self.assertEqual(notice.sent_at, "2026-11-20T11:30:00+00:00")
        self.assertEqual(notice.to_dict()["confirmation"], "RKN-2026-001")

    def test_remaining_uml_domain_models(self) -> None:
        user = User(id=1, username="ib", full_name="Иванов А.", role="ib_specialist", active=1)  # type: ignore[arg-type]
        self.assertIs(user.role, Role.SECURITY_SPECIALIST)
        self.assertIs(user.active, True)
        self.assertEqual(user.to_dict()["username"], "ib")

        comp = Computer(hostname="WS-FIN-04")
        dept = Department(name="Бухгалтерия")
        site = Site(name="Объект Север", address="ул. Строителей, 10")
        self.assertEqual(comp.to_dict(), {"hostname": "WS-FIN-04"})
        self.assertEqual(dept.to_dict(), {"name": "Бухгалтерия"})
        self.assertEqual(site.to_dict(), {"name": "Объект Север", "address": "ул. Строителей, 10"})

        msg = IncomingMessage(
            id=1,
            incident_id=2,
            source=SourceType.EMAIL.value,
            sender="sec@corp.local",
            body="Phishing alert",
            incident_key="mail-1",
            received_at="2026-11-20T10:00:00+00:00",
        )
        hist = HistoryRecord(
            id=1,
            incident_id=2,
            user_id=1,
            action="create",
            details="Created",
            created_at="2026-11-20T10:00:00+00:00",
            username="ib",
            full_name="Иванов А.",
        )
        ver = InstructionVersion(version=2, steps=["Шаг 1", "Шаг 2"], created_at="2026-11-20T09:00:00+00:00")
        instr = Instruction(id=1, title="Вирус", incident_type=IncidentType.VIRUS.value, steps=["Шаг 1"], version=2)
        prog = InstructionProgress(
            incident_id=2,
            step_index=0,
            completed=1,  # type: ignore[arg-type]
            updated_by=1,
            updated_at="2026-11-20T10:05:00+00:00",
        )
        self.assertIs(prog.completed, True)
        self.assertEqual(msg.to_dict()["incident_key"], "mail-1")
        self.assertEqual(hist.to_dict()["username"], "ib")
        self.assertEqual(ver.to_dict()["version"], 2)
        self.assertEqual(instr.to_dict()["steps"], ["Шаг 1"])
        self.assertIs(prog.to_dict()["completed"], True)

        measure = FollowUpMeasure(
            id=1,
            incident_id=2,
            cause="Открытый порт",
            action="Закрыть RDP",
            responsible_id=2,
            due_date="2026-11-25T00:00:00+00:00",
            status=TaskStatus.OPEN.value,
            result="",
        )
        att = Attachment(
            id=1,
            incident_id=2,
            filename="log.txt",
            mime_type="text/plain",
            path="/tmp/log.txt",
            uploaded_by=1,
            uploaded_at="2026-11-20T10:00:00+00:00",
        )
        deadlines = Deadlines(
            detected_at="2026-11-20T10:00:00+00:00",
            deadline_24h="2026-11-21T10:00:00+00:00",
            deadline_72h="2026-11-23T10:00:00+00:00",
            overdue_24h=False,
            overdue_72h=False,
        )
        notif = Notification(
            id=1,
            incident_id=2,
            recipient_role=Role.IT_HEAD.value,
            recipient_name="Сидорова Е.",
            kind="escalation_30m",
            message="Требуется реакция",
            created_at="2026-11-20T10:40:00+00:00",
        )
        audit = AuditRecord(
            id=1,
            user_id=1,
            object_type="incident",
            object_id=2,
            action="view",
            created_at="2026-11-20T10:00:00+00:00",
        )
        ing_err = IngestionError(
            id=1,
            source="zabbix",
            error_text="Empty body",
            occurred_at="2026-11-20T10:00:00+00:00",
            resolved=0,  # type: ignore[arg-type]
        )
        rep = ReportFile(
            period="2026-11",
            format="pdf",  # type: ignore[arg-type]
            created_at="2026-11-20T10:00:00+00:00",
            data={"total": 3},
        )
        self.assertEqual(measure.to_dict()["action"], "Закрыть RDP")
        self.assertEqual(att.to_dict()["filename"], "log.txt")
        self.assertEqual(deadlines.to_dict()["deadline_24h"], "2026-11-21T10:00:00+00:00")
        self.assertEqual(notif.to_dict()["channel"], Channel.INTERNAL)
        self.assertEqual(notif.to_dict()["status"], DeliveryStatus.SENT)
        self.assertEqual(audit.to_dict()["object_type"], "incident")
        self.assertIs(ing_err.resolved, False)
        self.assertEqual(ing_err.to_dict()["source"], "zabbix")
        self.assertIs(rep.format, ReportFormat.PDF)
        self.assertEqual(rep.to_dict()["data"], {"total": 3})


class TestIntegrationLayer(unittest.TestCase):
    def test_source_adapters_and_registry(self) -> None:
        self.assertEqual(
            set(ADAPTER_REGISTRY.keys()),
            {SourceType.KASPERSKY, SourceType.ZABBIX, SourceType.EMAIL, SourceType.TELEGRAM},
        )
        for adapter in ADAPTER_REGISTRY.values():
            self.assertIsInstance(adapter, SourceAdapter)
            self.assertEqual(adapter.poll(), [])

        kasp = KasperskyAdapter()
        k_norm = kasp.normalize(
            {
                "ksc_server": "KSC-01",
                "workstation": "WS-FIN-09",
                "account": "Петров",
                "threat": "Trojan.Win32",
                "event_id": "evt-99",
                "severity": "critical",
            }
        )
        self.assertEqual(k_norm["source"], SourceType.KASPERSKY.value)
        self.assertEqual(k_norm["incident_type"], IncidentType.VIRUS.value)
        self.assertEqual(k_norm["computer"], "WS-FIN-09")
        self.assertEqual(k_norm["body"], "Trojan.Win32")
        self.assertEqual(k_norm["incident_key"], "evt-99")
        self.assertEqual(k_norm["severity"], Severity.CRITICAL.value)

        zbx = ZabbixAdapter()
        z_norm = zbx.normalize(
            {
                "proxy": "zbx-proxy-1",
                "host": "SRV-DB-02",
                "owner": "Дежурный",
                "trigger": "Disk 98% full",
                "trigger_id": "trg-404",
            }
        )
        self.assertEqual(z_norm["source"], SourceType.ZABBIX.value)
        self.assertEqual(z_norm["incident_type"], IncidentType.OTHER.value)
        self.assertEqual(z_norm["computer"], "SRV-DB-02")
        self.assertEqual(z_norm["body"], "Disk 98% full")

        mail = MailAdapter()
        m_norm = mail.normalize(
            {
                "from_addr": "evil@phish.test",
                "recipient": "бухгалтер",
                "subject": "Срочный счет",
                "text": "Перейдите по ссылке",
                "message_id": "<msg-123>",
                "has_personal_data": True,
            }
        )
        self.assertEqual(m_norm["source"], SourceType.EMAIL.value)
        self.assertEqual(m_norm["incident_type"], IncidentType.PHISHING.value)
        self.assertEqual(m_norm["title"], "Срочный счет")
        self.assertEqual(m_norm["has_personal_data"], 1)

        tg = TelegramAdapter()
        t_norm = tg.normalize(
            {
                "chat_id": "9001",
                "full_name": "Сидоров В.П.",
                "text": "Странное письмо",
                "update_id": "upd-77",
            }
        )
        self.assertEqual(t_norm["source"], SourceType.TELEGRAM.value)
        self.assertEqual(t_norm["sender"], "9001")
        self.assertTrue(tg.send_message("9001", "Принято"))
        self.assertTrue(tg.reply_number("9001", 15))
        self.assertFalse(tg.send_message("", "empty target"))
        self.assertFalse(tg.reply_number("9001", 0))
        self.assertEqual(
            tg.sent_messages[-1],
            {"user": "9001", "text": "Инцидент #15 зарегистрирован"},
        )

    def test_local_and_domain_auth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "auth.db")
            container = AppContainer(db_path=db_path)
            container.init_db()
            container.user_repo.create(
                "inactive_user",
                hash_password("password123"),
                "Неактивный",
                Role.EMPLOYEE,
                active=False,
            )

            local = LocalAuth(container.user_repo)
            self.assertIsInstance(local, AuthProvider)
            ib_user = local.authenticate("ib", "password123")
            self.assertIsNotNone(ib_user)
            self.assertIs(ib_user.role, Role.SECURITY_SPECIALIST)
            self.assertIsNone(local.authenticate("ib", "wrong"))
            self.assertIsNone(local.authenticate("missing", "password123"))
            self.assertIsNone(local.authenticate("", "password123"))
            self.assertIsNone(local.authenticate("inactive_user", "password123"))

            # Domain unavailable -> delegates to LocalAuth
            dom_off = DomainAuth(local, domain_available=False)
            self.assertIsNotNone(dom_off.authenticate("ib", "password123"))
            self.assertIsNone(dom_off.authenticate("ib", "wrong"))

            # Domain available -> uses AD verifier, denies false, blocks inactive
            dom_on = DomainAuth(
                local,
                domain_available=True,
                ad_verifier=lambda u, p: p == "ad-secret",
            )
            self.assertIsNotNone(dom_on.authenticate("ib", "ad-secret"))
            self.assertIsNone(dom_on.authenticate("ib", "password123"))
            self.assertIsNone(dom_on.authenticate("inactive_user", "ad-secret"))

            # AD outage -> falls back to LocalAuth
            def failing_ad(_u: str, _p: str) -> bool:
                raise ConnectionError("AD unreachable")

            dom_fallback = DomainAuth(local, domain_available=True, ad_verifier=failing_ad)
            self.assertIsNotNone(dom_fallback.authenticate("ib", "password123"))
            self.assertIsNone(dom_fallback.authenticate("ib", "wrong"))


class TestLegacyDatabaseMigration(unittest.TestCase):
    def test_safe_migration_on_legacy_sqlite_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "legacy.db")
            conn = sqlite3.connect(db_path)
            conn.executescript(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL
                );
                CREATE TABLE sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE instructions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    incident_type TEXT NOT NULL,
                    steps_json TEXT NOT NULL
                );
                CREATE TABLE incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    incident_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Новый',
                    outcome TEXT NOT NULL DEFAULT '',
                    computer TEXT NOT NULL DEFAULT '',
                    employee TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    incident_key TEXT NOT NULL DEFAULT '',
                    has_personal_data INTEGER NOT NULL DEFAULT 0,
                    instruction_id INTEGER,
                    rkn_draft TEXT NOT NULL DEFAULT '',
                    detected_at TEXT NOT NULL,
                    taken_at TEXT,
                    closed_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    source TEXT NOT NULL DEFAULT '',
                    sender TEXT NOT NULL DEFAULT '',
                    body TEXT NOT NULL,
                    incident_key TEXT NOT NULL DEFAULT '',
                    received_at TEXT NOT NULL
                );
                CREATE TABLE history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE step_progress (
                    incident_id INTEGER NOT NULL,
                    step_index INTEGER NOT NULL,
                    completed INTEGER NOT NULL DEFAULT 0,
                    updated_by INTEGER,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (incident_id, step_index)
                );
                CREATE TABLE tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    assigned_to INTEGER,
                    status TEXT NOT NULL DEFAULT 'Открыта',
                    result TEXT NOT NULL DEFAULT '',
                    created_by INTEGER,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER,
                    recipient_role TEXT NOT NULL,
                    recipient_name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
                ("legacy_ib", hash_password("secret"), "Legacy IB", Role.SECURITY_SPECIALIST.value),
            )
            conn.execute(
                """
                INSERT INTO incidents (
                    title, description, incident_type, severity, status,
                    computer, employee, has_personal_data, detected_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "Legacy Virus",
                    "Legacy desc",
                    IncidentType.VIRUS.value,
                    Severity.HIGH.value,
                    IncidentStatus.NEW.value,
                    "WS-LEGACY",
                    "Иванов",
                    0,
                    "2026-11-19T10:00:00+00:00",
                    "2026-11-19T10:00:00+00:00",
                    "2026-11-19T10:00:00+00:00",
                ),
            )
            conn.execute(
                """
                INSERT INTO tasks (incident_id, title, assigned_to, created_by, created_at)
                VALUES (1, 'Legacy task', 1, 1, '2026-11-19T10:05:00+00:00')
                """
            )
            conn.execute(
                """
                INSERT INTO notifications (incident_id, recipient_role, recipient_name, kind, message, created_at)
                VALUES (1, 'it_head', 'Head', 'escalation_30m', 'Legacy alert', '2026-11-19T10:45:00+00:00')
                """
            )
            conn.commit()
            conn.close()

            db = Database(db_path)
            db.init_schema()
            # Re-running migration must remain idempotent.
            db.init_schema()

            with db.connection() as migrated:
                tables = {
                    row["name"]
                    for row in migrated.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                expected_tables = {
                    "roles",
                    "incident_types",
                    "severities",
                    "incident_statuses",
                    "check_results",
                    "sources",
                    "access_categories",
                    "task_statuses",
                    "notification_channels",
                    "delivery_statuses",
                    "notification_kinds",
                    "history_actions",
                    "audit_object_types",
                    "audit_actions",
                    "mime_types",
                    "computers",
                    "employees",
                    "instruction_steps",
                    "dispatch_rules",
                    "dispatch_rule_urgent_roles",
                    "regulator_notices",
                    "task_assignees",
                    "attachments",
                    "telegram_settings",
                    "telegram_subscriptions",
                    "audit_log",
                    "ingestion_errors",
                }
                self.assertTrue(expected_tables.issubset(tables))

                backfilled = migrated.execute(
                    "SELECT task_id, user_id, position FROM task_assignees WHERE task_id = 1"
                ).fetchall()
                self.assertEqual([(r["task_id"], r["user_id"], r["position"]) for r in backfilled], [(1, 1, 0)])

                def cols(table: str) -> set[str]:
                    return {r["name"] for r in migrated.execute(f"PRAGMA table_info({table})").fetchall()}

                self.assertTrue({"role_id", "active"}.issubset(cols("users")))
                self.assertNotIn("role", cols("users"))
                self.assertTrue({"status_id", "due_date"}.issubset(cols("tasks")))
                self.assertFalse({"status", "assigned_to"}.intersection(cols("tasks")))
                self.assertTrue({"task_id", "size_bytes", "mime_type_id"}.issubset(cols("attachments")))
                self.assertNotIn("mime_type", cols("attachments"))
                self.assertTrue({"role_id", "min_severity_id"}.issubset(cols("telegram_subscriptions")))
                self.assertFalse({"role", "min_severity"}.intersection(cols("telegram_subscriptions")))
                self.assertTrue(
                    {"incident_type_id", "severity_id", "status_id", "access_category_id", "assigned_to"}.issubset(
                        cols("incidents")
                    )
                )
                self.assertFalse({"rkn_draft", "rkn_sent_at", "rkn_confirmation"}.intersection(cols("incidents")))
                self.assertTrue({"recipient_role_id", "kind_id", "channel_id", "status_id"}.issubset(cols("notifications")))
                self.assertTrue({"incident_type_id", "version"}.issubset(cols("instructions")))
                self.assertNotIn("steps_json", cols("instructions"))

            container = AppContainer(db_path=db_path)
            users = container.user_repo.list_all()
            self.assertEqual(len(users), 1)
            self.assertEqual(users[0].username, "legacy_ib")
            self.assertTrue(users[0].active)

            inc = container.incident_repo.get_by_id(1)
            self.assertIsNotNone(inc)
            self.assertEqual(inc.access_category, AccessCategory.EMPLOYEE_INVOLVED.value)

            tasks = container.task_repo.list_by_incident(1)
            self.assertEqual(len(tasks), 1)
            self.assertIsNone(tasks[0].due_date)
            self.assertEqual(tasks[0].assignee_ids, [1])

            notifs = container.notification_repo.list_all()
            self.assertEqual(len(notifs), 1)
            self.assertEqual(notifs[0].channel, Channel.INTERNAL.value)
            self.assertEqual(notifs[0].status, DeliveryStatus.SENT.value)


class TestServicesViaAppContainer(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._tmp_dir.name) / "uml_services.db")
        self.container = AppContainer(db_path=self.db_path)
        self.container.init_db()
        tg = self.container.adapters.get(SourceType.TELEGRAM)
        if isinstance(tg, TelegramAdapter):
            tg.sent_messages.clear()

        self.ib = self.container.user_repo.get_by_username("ib")
        self.sysadmin = self.container.user_repo.get_by_username("sysadmin")
        self.it_head = self.container.user_repo.get_by_username("it_head")
        self.lawyer = self.container.user_repo.get_by_username("lawyer")
        assert self.ib and self.sysadmin and self.it_head and self.lawyer

        self.director = self.container.user_repo.create(
            "director", hash_password("password123"), "Директор И.И.", Role.DIRECTOR
        )
        self.accountant = self.container.user_repo.create(
            "accountant", hash_password("password123"), "Главбух П.П.", Role.ACCOUNTANT
        )
        self.foreman = self.container.user_repo.create(
            "foreman", hash_password("password123"), "Прораб С.С.", Role.FOREMAN
        )
        self.employee = self.container.user_repo.create(
            "employee", hash_password("password123"), "Сотрудник К.К.", Role.EMPLOYEE
        )

    def tearDown(self) -> None:
        self._tmp_dir.cleanup()

    def test_container_wiring_and_dynamic_db_path(self) -> None:
        self.assertIsInstance(self.container.access_service, AccessControlService)
        self.assertIsInstance(self.container.deduplication_service, DeduplicationService)
        self.assertIsInstance(self.container.ingestion_service, IngestionService)
        self.assertIsInstance(self.container.incident_service, IncidentService)
        self.assertIsInstance(self.container.instruction_service, InstructionService)
        self.assertIsInstance(self.container.task_service, TaskService)
        self.assertIsInstance(self.container.deadline_service, DeadlineService)
        self.assertIsInstance(self.container.notification_service, NotificationService)
        self.assertIsInstance(self.container.escalation_service, EscalationService)
        self.assertIsInstance(self.container.report_service, ReportService)

        prev = os.environ.get("DB_PATH")
        try:
            os.environ["DB_PATH"] = self.db_path
            shared = get_container()
            self.assertEqual(shared.db.resolve_path(), self.db_path)
            self.assertIsNotNone(shared.user_repo.get_by_username("director"))
        finally:
            if prev is None:
                os.environ.pop("DB_PATH", None)
            else:
                os.environ["DB_PATH"] = prev

    def test_access_control_service_matrix_and_audit(self) -> None:
        tech_inc = Incident(id=101, computer="SRV-01", employee="", has_personal_data=0)
        emp_inc = Incident(id=102, computer="WS-02", employee="Иванов", has_personal_data=0)
        pdn_inc = Incident(id=103, computer="CRM-01", employee="Волков", has_personal_data=1)
        inactive = User(id=999, username="off", full_name="Уволен", role=Role.SECURITY_SPECIALIST, active=False)

        access = self.container.access_service
        self.assertFalse(access.can_view(inactive, tech_inc))
        self.assertTrue(access.can_view(self.employee, tech_inc))
        self.assertFalse(access.can_view(self.employee, emp_inc))
        self.assertTrue(access.can_view(self.foreman, emp_inc))
        self.assertFalse(access.can_view(self.foreman, pdn_inc))
        self.assertFalse(access.can_view(self.sysadmin, pdn_inc))
        self.assertTrue(access.can_view(self.director, pdn_inc))
        self.assertTrue(access.can_view(self.accountant, pdn_inc))

        self.assertTrue(access.can_edit(self.ib, pdn_inc))
        self.assertTrue(access.can_edit(self.sysadmin, emp_inc))
        self.assertFalse(access.can_edit(self.director, pdn_inc))
        self.assertFalse(access.can_edit(self.foreman, emp_inc))
        self.assertFalse(access.can_access_rkn(self.sysadmin))
        self.assertTrue(access.can_access_rkn(self.accountant))

        with self.assertRaises(AccessDeniedError):
            access.assert_incident_access(self.sysadmin, pdn_inc)
        with self.assertRaises(AccessDeniedError):
            access.assert_incident_access(self.director, pdn_inc, edit=True)
        with self.assertRaises(AccessDeniedError):
            access.assert_rkn_access(self.sysadmin)

        recent = self.container.audit_repo.list_recent(limit=10)
        actions = {(r.user_id, r.object_type, r.action) for r in recent}
        self.assertIn((self.sysadmin.id, "incident", "access_denied"), actions)
        self.assertIn((self.director.id, "incident", "edit_denied"), actions)
        self.assertIn((self.sysadmin.id, "regulator_notice", "access_denied"), actions)

    def test_ingestion_and_deduplication_services(self) -> None:
        ing = self.container.ingestion_service
        dedup = self.container.deduplication_service

        # Telegram signal normalization + reply_number
        tg_res = ing.receive(
            {
                "source": "telegram",
                "chat_id": "tg-chat-77",
                "full_name": "Кузнецов",
                "text": "Пришло странное вложение",
                "incident_type": "phishing",
                "severity": "high",
                "update_id": "tg-upd-1",
            }
        )
        self.assertFalse(tg_res["deduplicated"])
        tg_inc_id = tg_res["incident_id"]

        tg_adapter = self.container.adapters[SourceType.TELEGRAM]
        assert isinstance(tg_adapter, TelegramAdapter)
        self.assertIn(
            {"user": "tg-chat-77", "text": f"Инцидент #{tg_inc_id} зарегистрирован"},
            tg_adapter.sent_messages,
        )

        # Deduplication by incident_key and by (computer, incident_type)
        self.assertTrue(dedup.is_duplicate("tg-upd-1", "", ""))
        dup_res = ing.receive(
            {
                "source": "email",
                "from_addr": "soc@corp.local",
                "body": "Повтор фишинга",
                "incident_key": "tg-upd-1",
            }
        )
        self.assertTrue(dup_res["deduplicated"])
        self.assertEqual(dup_res["incident_id"], tg_inc_id)

        # Unregistered adapter source (DLP) + computer+type dedup
        dlp_res = ing.receive(
            {
                "source": "dlp",
                "sender": "DLP-01",
                "body": "Попытка выгрузки",
                "computer": "WS-DLP-9",
                "incident_type": "data_leak",
                "has_personal_data": 1,
            }
        )
        self.assertFalse(dlp_res["deduplicated"])
        self.assertTrue(dedup.is_duplicate("", "WS-DLP-9", IncidentType.DATA_LEAK.value))

        # Malformed signal logs IngestionError and raises ValidationError
        with self.assertRaises(ValidationError):
            ing.receive({"source": "zabbix", "body": "   "})
        errors = self.container.ingestion_error_repo.list_all(resolved=False)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].source, "zabbix")
        resolved_err = self.container.ingestion_error_repo.mark_resolved(errors[0].id)
        self.assertIsNotNone(resolved_err)
        self.assertTrue(resolved_err.resolved)

    def test_incident_instruction_and_task_services(self) -> None:
        inc_svc = self.container.incident_service
        instr_svc = self.container.instruction_service
        task_svc = self.container.task_service

        created = inc_svc.create_incident(
            self.ib,
            {
                "title": "Подозрительная активность",
                "description": "Проверка",
                "incident_type": "bruteforce",
                "severity": "medium",
                "source": "manual",
                "computer": "SRV-AUTH-1",
                "employee": "",
                "has_personal_data": 0,
            },
        )
        inc_id = created["id"]
        self.assertEqual(created["access_category"], AccessCategory.TECHNICAL.value)

        classified = inc_svc.classify(self.ib, inc_id, "virus", "critical")
        self.assertEqual(classified["incident_type"], IncidentType.VIRUS.value)
        self.assertEqual(classified["severity"], Severity.CRITICAL.value)
        self.assertEqual(classified["instruction_id"], 1)

        updated = inc_svc.update_incident(
            self.ib,
            inc_id,
            {"employee": "Морозов А.А.", "assigned_to": self.sysadmin.id},
        )
        self.assertEqual(updated["access_category"], AccessCategory.EMPLOYEE_INVOLVED.value)
        self.assertEqual(updated["assigned_to"], self.sysadmin.id)

        # Lifecycle transitions via service
        in_work = inc_svc.change_status(self.sysadmin, inc_id, IncidentStatus.IN_PROGRESS)
        self.assertEqual(in_work["status"], IncidentStatus.IN_PROGRESS.value)
        self.assertIsNotNone(in_work["taken_at"])

        in_review = inc_svc.change_status(self.sysadmin, inc_id, IncidentStatus.IN_REVIEW)
        self.assertEqual(in_review["status"], IncidentStatus.IN_REVIEW.value)

        returned = inc_svc.change_status(
            self.ib, inc_id, IncidentStatus.IN_PROGRESS, outcome="Нужна доработка"
        )
        self.assertEqual(returned["status"], IncidentStatus.IN_PROGRESS.value)

        closed = inc_svc.change_status(self.ib, inc_id, IncidentStatus.CLOSED, outcome="resolved")
        self.assertEqual(closed["status"], IncidentStatus.CLOSED.value)
        self.assertEqual(closed["outcome"], CheckResult.RESOLVED.value)
        self.assertIsNotNone(closed["closed_at"])

        reopened = inc_svc.change_status(self.ib, inc_id, IncidentStatus.IN_PROGRESS)
        self.assertIsNone(reopened["closed_at"])

        custom_closed = inc_svc.change_status(
            self.ib, inc_id, "closed", outcome="Передано в СК/РКН"
        )
        self.assertEqual(custom_closed["outcome"], "Передано в СК/РКН")
        inc_svc.change_status(self.ib, inc_id, IncidentStatus.IN_PROGRESS)

        with self.assertRaises(ValidationError):
            inc_svc.change_status(self.ib, inc_id, "not_a_status")

        # Instructions & steps
        self.assertGreaterEqual(len(instr_svc.list_instructions()), 4)
        step = instr_svc.update_step(self.sysadmin, inc_id, 0, True)
        self.assertTrue(step["completed"])
        card = inc_svc.get_incident(self.ib, inc_id)
        self.assertEqual(card["step_progress"][0]["completed"], 1)

        # Tasks & overdue filtering
        past_due = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        future_due = (datetime.now(timezone.utc) + timedelta(hours=3)).isoformat()
        t1 = task_svc.create_task(
            self.ib,
            inc_id,
            {
                "title": "Просроченная",
                "description": "Проверить журнал авторизации",
                "assigned_to": self.sysadmin.id,
                "due_date": past_due,
            },
        )
        t2 = task_svc.create_task(
            self.ib,
            inc_id,
            {
                "title": "Плановая",
                "description": "Обновить политику паролей",
                "assigned_to": self.sysadmin.id,
                "due_date": future_due,
            },
        )
        t_pdn = task_svc.create_task(
            self.ib,
            2,
            {
                "title": "ПДн-задача",
                "description": "Проверить доступ к ПДн",
                "assigned_to": self.sysadmin.id,
                "due_date": past_due,
            },
        )

        self.assertEqual(t1["assigned_to"], self.sysadmin.id)
        sys_tasks = task_svc.list_tasks(self.sysadmin, assigned_to="me")
        self.assertIn(t1["id"], {t["id"] for t in sys_tasks})
        self.assertNotIn(t_pdn["id"], {t["id"] for t in sys_tasks})

        sys_overdue = {t["id"] for t in task_svc.list_overdue(self.sysadmin)}
        self.assertIn(t1["id"], sys_overdue)
        self.assertNotIn(t2["id"], sys_overdue)
        self.assertNotIn(t_pdn["id"], sys_overdue)

        ib_overdue = {t["id"] for t in task_svc.list_overdue(self.ib)}
        self.assertIn(t_pdn["id"], ib_overdue)

        done = task_svc.update_task(
            self.sysadmin, t1["id"], {"status": "done", "result": "Выполнено"}
        )
        self.assertEqual(done["status"], TaskStatus.DONE.value)
        self.assertNotIn(t1["id"], {t["id"] for t in task_svc.list_overdue(self.ib)})

        with self.assertRaises(NotFoundError):
            inc_svc.get_incident(self.ib, 999999)

    def test_deadlines_notifications_escalation_and_reports(self) -> None:
        dl_svc = self.container.deadline_service
        notif_svc = self.container.notification_service
        esc_svc = self.container.escalation_service
        rep_svc = self.container.report_service

        old_detected = (datetime.now(timezone.utc) - timedelta(hours=80)).replace(microsecond=0).isoformat()
        deadlines = dl_svc.calculate(old_detected)
        self.assertTrue(deadlines.overdue_24h)
        self.assertTrue(deadlines.overdue_72h)
        self.assertLess(dl_svc.remaining(deadlines.deadline_24h), timedelta(0))

        # Incident #2 is seeded PDn incident
        notice = dl_svc.get_notice(self.lawyer, 2)
        self.assertTrue(notice["is_auto_generated"])
        edited = dl_svc.update_draft(self.lawyer, 2, "Обновленный текст для РКН")
        self.assertFalse(edited["is_auto_generated"])
        sent = dl_svc.mark_sent(self.lawyer, 2, "РКН-КВИТАНЦИЯ-88")
        self.assertEqual(sent["confirmation"], "РКН-КВИТАНЦИЯ-88")
        self.assertIsNotNone(sent["sent_at"])

        # Notifications: urgent deduplication, Telegram channel, broadcast
        tg_notif = notif_svc.notify_urgent(
            incident_id=1,
            recipient_role=Role.IT_HEAD,
            recipient_name="Сидорова Елена",
            kind="urgent_test",
            message="Срочный алерт",
            channel=Channel.TELEGRAM,
        )
        self.assertIsNotNone(tg_notif)
        self.assertEqual(tg_notif["channel"], Channel.TELEGRAM.value)
        self.assertIsNone(
            notif_svc.notify_urgent(
                incident_id=1,
                recipient_role=Role.IT_HEAD,
                recipient_name="Сидорова Елена",
                kind="urgent_test",
                message="Дубль",
            )
        )
        tg_adapter = self.container.adapters[SourceType.TELEGRAM]
        assert isinstance(tg_adapter, TelegramAdapter)
        self.assertIn({"user": "Сидорова Елена", "text": "Срочный алерт"}, tg_adapter.sent_messages)

        broadcasted = notif_svc.broadcast_warning(
            "Внимание: фишинг", [Role.FOREMAN.value, "ib"]
        )
        self.assertEqual(len(broadcasted), 2)
        self.assertEqual(
            len(notif_svc.list_notifications(recipient_role=Role.FOREMAN.value)), 1
        )

        # Escalations: timeout_min=30, check_unaccepted_high_severity, call_next, stop
        self.assertEqual(esc_svc.timeout_min, 30)
        unaccepted = esc_svc.check_unaccepted_high_severity()
        self.assertTrue(any(n["incident_id"] == 1 and n["kind"] == "escalation_30m" for n in unaccepted))
        self.assertEqual(esc_svc.check_unaccepted_high_severity(), [])

        # Chain call_next on seeded incident #1 advances from IT_HEAD -> DIRECTOR -> None
        inc1 = self.container.incident_repo.get_by_id(1)
        assert inc1 is not None
        step2 = esc_svc.call_next(inc1)
        self.assertIsNotNone(step2)
        self.assertEqual(step2["recipient_role"], Role.DIRECTOR.value)
        self.assertEqual(step2["kind"], "escalation_director")
        self.assertIsNone(esc_svc.call_next(inc1))

        # Create a fresh overdue high-severity incident and stop its escalations
        fresh_inc = self.container.incident_repo.create(
            Incident(
                title="Останавливаемая эскалация",
                incident_type=IncidentType.VIRUS.value,
                severity=Severity.HIGH.value,
                status=IncidentStatus.NEW.value,
                detected_at=(datetime.now(timezone.utc) - timedelta(minutes=50)).isoformat(),
            )
        )
        esc_svc.stop(fresh_inc)
        self.assertIsNone(esc_svc.call_next(fresh_inc))
        self.assertFalse(
            any(n["incident_id"] == fresh_inc.id for n in esc_svc.check_unaccepted_high_severity())
        )

        # Full check_escalations still handles PDn notices on incident #2
        pdn_notices = esc_svc.check_escalations()
        self.assertEqual(
            {(n["incident_id"], n["kind"]) for n in pdn_notices},
            {(2, "pdn_lawyer_notice"), (2, "pdn_accounting_notice")},
        )

        # Reports: monthly, yearly, and export_report
        now = datetime.now(timezone.utc)
        monthly = rep_svc.monthly_report(now.year, now.month)
        self.assertGreaterEqual(monthly["total"], 4)
        self.assertEqual(monthly["personal_data_count"], 1)

        yearly = rep_svc.year_stats(now.year)
        self.assertEqual(yearly["year"], now.year)
        self.assertIn(f"{now.year:04d}-{now.month:02d}", yearly["by_month"])

        exported = rep_svc.export_report(f"{now.year:04d}-{now.month:02d}", ReportFormat.WORD, monthly)
        self.assertIsInstance(exported, ReportFile)
        self.assertIs(exported.format, ReportFormat.WORD)
        self.assertEqual(exported.data["total"], monthly["total"])


if __name__ == "__main__":
    unittest.main()
