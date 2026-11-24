import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.container import AppContainer
from app.domain.models import Incident
from app.enums import (
    AccessCategory,
    Channel,
    CheckResult,
    DeliveryStatus,
    IncidentStatus,
    IncidentType,
    Role,
    Severity,
    SourceType,
    TaskStatus,
)
from app.repositories import Database, hash_password


class TestNormalizedDatabaseSchema(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._tmp_dir.name) / "normalized.db")
        self.container = AppContainer(db_path=self.db_path)
        self.container.init_db()

    def tearDown(self) -> None:
        self._tmp_dir.cleanup()

    def test_enum_lookup_tables_and_dispatch_rules_populated(self) -> None:
        with self.container.db.connection() as conn:
            self.assertEqual(
                {r["code"] for r in conn.execute("SELECT code FROM roles").fetchall()},
                {r.value for r in Role},
            )
            self.assertEqual(
                {r["name"] for r in conn.execute("SELECT name FROM incident_types").fetchall()},
                {t.value for t in IncidentType},
            )
            self.assertEqual(
                {
                    (r["code"], r["weight"])
                    for r in conn.execute("SELECT code, weight FROM severities").fetchall()
                },
                {(s.value, s.weight) for s in Severity},
            )
            self.assertEqual(
                {r["name"] for r in conn.execute("SELECT name FROM incident_statuses").fetchall()},
                {s.value for s in IncidentStatus},
            )
            self.assertEqual(
                {r["name"] for r in conn.execute("SELECT name FROM check_results").fetchall()},
                {c.value for c in CheckResult},
            )
            self.assertEqual(
                {r["name"] for r in conn.execute("SELECT name FROM sources").fetchall()},
                {s.value for s in SourceType},
            )
            self.assertEqual(
                {r["name"] for r in conn.execute("SELECT name FROM access_categories").fetchall()},
                {a.value for a in AccessCategory},
            )
            self.assertEqual(
                {r["name"] for r in conn.execute("SELECT name FROM task_statuses").fetchall()},
                {t.value for t in TaskStatus},
            )
            self.assertEqual(
                {r["name"] for r in conn.execute("SELECT name FROM notification_channels").fetchall()},
                {c.value for c in Channel},
            )
            self.assertEqual(
                {r["name"] for r in conn.execute("SELECT name FROM delivery_statuses").fetchall()},
                {d.value for d in DeliveryStatus},
            )

            rule_count = conn.execute("SELECT COUNT(*) FROM dispatch_rules").fetchone()[0]
            self.assertEqual(rule_count, len(IncidentType))
            urgent_pairs = {
                (r["inc_code"], r["role_code"])
                for r in conn.execute(
                    """
                    SELECT it.code AS inc_code, r.code AS role_code
                    FROM dispatch_rule_urgent_roles drur
                    JOIN incident_types it ON it.id = drur.incident_type_id
                    JOIN roles r ON r.id = drur.role_id
                    """
                ).fetchall()
            }
            self.assertEqual(
                urgent_pairs,
                {
                    (IncidentType.DATA_LEAK.name, Role.LAWYER.value),
                    (IncidentType.PAYMENT_FRAUD.name, Role.ACCOUNTANT.value),
                },
            )

    def test_1nf_instruction_steps_and_step_progress_fk(self) -> None:
        instructions = self.container.instruction_repo.list_all()
        self.assertEqual(len(instructions), 4)
        self.assertGreater(len(instructions[0].steps), 0)

        ib = self.container.user_repo.get_by_username("ib")
        assert ib is not None
        self.container.instruction_repo.upsert_progress(1, 0, True, ib.id)

        with self.container.db.connection() as conn:
            step_rows = conn.execute(
                "SELECT * FROM instruction_steps WHERE instruction_id = 1 ORDER BY step_index"
            ).fetchall()
            self.assertEqual([r["step_text"] for r in step_rows], instructions[0].steps)

            prog = conn.execute(
                "SELECT instruction_step_id, completed FROM step_progress WHERE incident_id = 1 AND step_index = 0"
            ).fetchone()
            self.assertIsNotNone(prog)
            self.assertEqual(prog["instruction_step_id"], step_rows[0]["id"])
            self.assertEqual(prog["completed"], 1)

    def test_3nf_computers_employees_regulator_notices_and_outcome_split(self) -> None:
        inc_a = self.container.incident_repo.create(
            Incident(
                title="Инцидент A",
                incident_type=IncidentType.VIRUS.value,
                severity=Severity.HIGH.value,
                status=IncidentStatus.CLOSED.value,
                outcome=CheckResult.RESOLVED.value,
                computer="WS-SHARED-01",
                employee="Ковалев А.А.",
                source=SourceType.KASPERSKY.value,
                detected_at="2026-11-20T10:00:00+00:00",
            )
        )
        inc_b = self.container.incident_repo.create(
            Incident(
                title="Инцидент B",
                incident_type=IncidentType.PHISHING.value,
                severity=Severity.MEDIUM.value,
                status=IncidentStatus.CLOSED.value,
                outcome="Передано в СК/РКН",
                computer="WS-SHARED-01",
                employee="Ковалев А.А.",
                source=SourceType.EMAIL.value,
                has_personal_data=1,
                rkn_draft="Черновик РКН",
                rkn_sent_at="2026-11-20T12:00:00+00:00",
                rkn_confirmation="RKN-007",
                detected_at="2026-11-20T11:00:00+00:00",
            )
        )

        with self.container.db.connection() as conn:
            # Shared computer and employee stored once in lookup/entity tables.
            comp_rows = conn.execute(
                "SELECT id FROM computers WHERE hostname = ?", ("WS-SHARED-01",)
            ).fetchall()
            emp_rows = conn.execute(
                "SELECT id FROM employees WHERE full_name = ?", ("Ковалев А.А.",)
            ).fetchall()
            self.assertEqual(len(comp_rows), 1)
            self.assertEqual(len(emp_rows), 1)

            row_a = conn.execute(
                "SELECT check_result_id, outcome_note FROM incidents WHERE id = ?", (inc_a.id,)
            ).fetchone()
            self.assertIsNotNone(row_a["check_result_id"])
            self.assertEqual(row_a["outcome_note"], "")

            row_b = conn.execute(
                "SELECT check_result_id, outcome_note FROM incidents WHERE id = ?", (inc_b.id,)
            ).fetchone()
            self.assertIsNone(row_b["check_result_id"])
            self.assertEqual(row_b["outcome_note"], "Передано в СК/РКН")

            rn_a = conn.execute(
                "SELECT * FROM regulator_notices WHERE incident_id = ?", (inc_a.id,)
            ).fetchone()
            rn_b = conn.execute(
                "SELECT * FROM regulator_notices WHERE incident_id = ?", (inc_b.id,)
            ).fetchone()
            self.assertIsNone(rn_a)
            self.assertIsNotNone(rn_b)
            self.assertEqual(rn_b["draft"], "Черновик РКН")
            self.assertEqual(rn_b["confirmation"], "RKN-007")

            # Integrity constraints reject invalid foreign keys and boolean flags.
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO users (username, password_hash, full_name, role_id, active) VALUES ('bad', 'h', 'Bad', 9999, 1)"
                )
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO users (username, password_hash, full_name, role_id, active) VALUES ('bad2', 'h', 'Bad2', 1, 2)"
                )

    def test_pre_audit_11_table_schema_migrates_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pre_path = str(Path(tmp) / "pre_audit.db")
            conn = sqlite3.connect(pre_path)
            conn.executescript(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
                    instruction_id INTEGER REFERENCES instructions(id),
                    rkn_draft TEXT NOT NULL DEFAULT '',
                    detected_at TEXT NOT NULL,
                    taken_at TEXT,
                    closed_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    access_category TEXT NOT NULL DEFAULT '',
                    assigned_to INTEGER REFERENCES users(id),
                    rkn_sent_at TEXT,
                    rkn_confirmation TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                    source TEXT NOT NULL DEFAULT '',
                    sender TEXT NOT NULL DEFAULT '',
                    body TEXT NOT NULL,
                    incident_key TEXT NOT NULL DEFAULT '',
                    received_at TEXT NOT NULL
                );
                CREATE TABLE history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                    user_id INTEGER REFERENCES users(id),
                    action TEXT NOT NULL,
                    details TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE step_progress (
                    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                    step_index INTEGER NOT NULL,
                    completed INTEGER NOT NULL DEFAULT 0,
                    updated_by INTEGER REFERENCES users(id),
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (incident_id, step_index)
                );
                CREATE TABLE tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    assigned_to INTEGER REFERENCES users(id),
                    status TEXT NOT NULL DEFAULT 'Открыта',
                    result TEXT NOT NULL DEFAULT '',
                    created_by INTEGER REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    due_date TEXT
                );
                CREATE TABLE notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
                    recipient_role TEXT NOT NULL,
                    recipient_name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    channel TEXT NOT NULL DEFAULT 'internal',
                    status TEXT NOT NULL DEFAULT 'sent'
                );
                CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id),
                    object_type TEXT NOT NULL,
                    object_id INTEGER,
                    action TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE ingestion_errors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL DEFAULT '',
                    error_text TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    resolved INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            conn.execute(
                "INSERT INTO users (id, username, password_hash, full_name, role, active) VALUES (1, 'ib', ?, 'ИБ', 'ib_specialist', 1)",
                (hash_password("password123"),),
            )
            conn.execute(
                "INSERT INTO sessions (token, user_id, created_at) VALUES ('tok-1', 1, '2026-11-20T10:00:00+00:00')"
            )
            conn.execute(
                "INSERT INTO instructions (id, title, incident_type, steps_json) VALUES (1, 'Вирус', 'Вирус / Вредоносное ПО', ?)",
                (json.dumps(["Шаг 1", "Шаг 2"], ensure_ascii=False),),
            )
            conn.execute(
                """
                INSERT INTO incidents (
                    id, title, description, incident_type, severity, status, outcome,
                    computer, employee, source, incident_key, has_personal_data,
                    instruction_id, rkn_draft, detected_at, created_at, updated_at,
                    access_category, assigned_to, rkn_sent_at, rkn_confirmation
                ) VALUES (
                    10, 'Утечка', 'Описание', 'Утечка ПДн', 'critical', 'Закрыт', 'Передано в СК/РКН',
                    'SRV-01', 'Волков', 'dlp', 'k-10', 1,
                    1, 'Черновик', '2026-11-20T09:00:00+00:00', '2026-11-20T09:00:00+00:00', '2026-11-20T12:00:00+00:00',
                    'personal_data', 1, '2026-11-20T11:00:00+00:00', 'RKN-10'
                )
                """
            )
            conn.execute(
                "INSERT INTO messages (id, incident_id, source, sender, body, incident_key, received_at) VALUES (5, 10, 'dlp', 'DLP', 'Alert', 'k-10', '2026-11-20T09:00:00+00:00')"
            )
            conn.execute(
                "INSERT INTO history (id, incident_id, user_id, action, details, created_at) VALUES (3, 10, 1, 'create', 'Created', '2026-11-20T09:00:00+00:00')"
            )
            conn.execute(
                "INSERT INTO step_progress (incident_id, step_index, completed, updated_by, updated_at) VALUES (10, 1, 1, 1, '2026-11-20T09:30:00+00:00')"
            )
            conn.execute(
                "INSERT INTO tasks (id, incident_id, title, description, assigned_to, status, result, created_by, created_at, due_date) VALUES (7, 10, 'T1', 'D1', 1, 'Выполнена', 'OK', 1, '2026-11-20T09:10:00+00:00', '2026-11-21T09:10:00+00:00')"
            )
            conn.execute(
                "INSERT INTO notifications (id, incident_id, recipient_role, recipient_name, kind, message, created_at, channel, status) VALUES (4, 10, 'lawyer', 'Анна', 'pdn_lawyer_notice', 'Msg', '2026-11-20T09:15:00+00:00', 'telegram', 'sent')"
            )
            conn.execute(
                "INSERT INTO audit_log (id, user_id, object_type, object_id, action, created_at) VALUES (8, 1, 'incident', 10, 'view', '2026-11-20T09:20:00+00:00')"
            )
            conn.execute(
                "INSERT INTO ingestion_errors (id, source, error_text, occurred_at, resolved) VALUES (2, 'unknown_feed', 'Bad JSON', '2026-11-20T09:25:00+00:00', 0)"
            )
            conn.commit()
            conn.close()

            db = Database(pre_path)
            db.init_schema()
            db.init_schema()

            migrated_container = AppContainer(db_path=pre_path)
            self.assertIsNotNone(migrated_container.session_repo.get_user_by_token("tok-1"))
            inst = migrated_container.instruction_repo.get_by_id(1)
            self.assertIsNotNone(inst)
            self.assertEqual(inst.steps, ["Шаг 1", "Шаг 2"])

            inc = migrated_container.incident_repo.get_by_id(10)
            self.assertIsNotNone(inc)
            self.assertEqual(inc.outcome, "Передано в СК/РКН")
            self.assertEqual(inc.computer, "SRV-01")
            self.assertEqual(inc.employee, "Волков")
            self.assertEqual(inc.rkn_draft, "Черновик")
            self.assertEqual(inc.rkn_confirmation, "RKN-10")

            self.assertEqual(len(migrated_container.message_repo.list_by_incident(10)), 1)
            self.assertEqual(migrated_container.history_repo.list_by_incident(10)[0].action, "create")
            self.assertEqual(migrated_container.task_repo.get_by_id(7).status, TaskStatus.DONE.value)
            notif = migrated_container.notification_repo.list_all()[0]
            self.assertEqual(notif.channel, Channel.TELEGRAM.value)
            self.assertEqual(migrated_container.audit_repo.list_recent()[0].object_type, "incident")
            self.assertEqual(migrated_container.ingestion_error_repo.list_all()[0].source, "unknown_feed")

            with db.connection() as check_conn:
                self.assertEqual(check_conn.execute("PRAGMA foreign_key_check").fetchall(), [])
                prog_row = check_conn.execute(
                    "SELECT instruction_step_id FROM step_progress WHERE incident_id = 10 AND step_index = 1"
                ).fetchone()
                self.assertIsNotNone(prog_row["instruction_step_id"])


if __name__ == "__main__":
    unittest.main()
