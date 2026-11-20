import os
import tempfile
import unittest
from enum import StrEnum
from pathlib import Path

from fastapi.testclient import TestClient

from app.enums import (
    DONE_TASK_STATUSES,
    AccessCategory,
    Channel,
    CheckResult,
    DeliveryStatus,
    IncidentStatus,
    IncidentType,
    PdnFlag,
    ReportFormat,
    Role,
    Severity,
    SourceType,
    TaskStatus,
)
from main import app


class TestAllTwelveEnums(unittest.TestCase):
    def test_all_twelve_enums_are_strenums_with_exact_members(self) -> None:
        all_enums = [
            Role,
            IncidentType,
            Severity,
            IncidentStatus,
            CheckResult,
            PdnFlag,
            AccessCategory,
            SourceType,
            TaskStatus,
            Channel,
            DeliveryStatus,
            ReportFormat,
        ]
        self.assertEqual(len(all_enums), 12)
        for enum_cls in all_enums:
            with self.subTest(enum=enum_cls.__name__):
                self.assertTrue(issubclass(enum_cls, StrEnum))
                self.assertGreater(len(enum_cls), 0)

        self.assertEqual(
            {m.name: m.value for m in IncidentType},
            {
                "PHISHING": "Фишинг",
                "VIRUS": "Вирус / Вредоносное ПО",
                "BRUTEFORCE": "Подбор пароля",
                "DATA_LEAK": "Утечка ПДн",
                "PAYMENT_FRAUD": "Обман с платежами",
                "UNAUTHORIZED_ACCESS": "Несанкционированный доступ",
                "CVE": "Уязвимость (CVE)",
                "OTHER": "Прочее",
            },
        )
        self.assertEqual(
            {m.name: m.value for m in Severity},
            {
                "LOW": "low",
                "MEDIUM": "medium",
                "HIGH": "high",
                "CRITICAL": "critical",
            },
        )
        self.assertEqual(
            {m.name: m.value for m in IncidentStatus},
            {
                "NEW": "Новый",
                "IN_PROGRESS": "В работе",
                "IN_REVIEW": "На проверке",
                "CLOSED": "Закрыт",
            },
        )
        self.assertEqual(
            {m.name: m.value for m in CheckResult},
            {
                "CONFIRMED": "Инцидент подтверждён",
                "RESOLVED": "Устранен",
                "FALSE_POSITIVE": "Ложное срабатывание",
                "NOT_CONFIRMED": "Не удалось подтвердить",
            },
        )
        self.assertEqual(
            {m.name: m.value for m in PdnFlag},
            {
                "YES": "yes",
                "NO": "no",
                "UNKNOWN": "unknown",
            },
        )
        self.assertEqual(
            {m.name: m.value for m in AccessCategory},
            {
                "TECHNICAL": "technical",
                "PERSONAL_DATA": "personal_data",
                "EMPLOYEE_INVOLVED": "employee_involved",
            },
        )
        self.assertEqual(
            {m.name: m.value for m in SourceType},
            {
                "KASPERSKY": "antivirus",
                "ZABBIX": "zabbix",
                "DLP": "dlp",
                "EMAIL": "mail_gateway",
                "TELEGRAM": "telegram",
                "MANUAL": "manual",
            },
        )
        self.assertEqual(
            {m.name: m.value for m in TaskStatus},
            {
                "OPEN": "Открыта",
                "DONE": "Выполнена",
                "OVERDUE": "Просрочена",
            },
        )
        self.assertEqual(
            {m.name: m.value for m in Channel},
            {
                "TELEGRAM": "telegram",
                "EMAIL": "email",
                "INTERNAL": "internal",
            },
        )
        self.assertEqual(
            {m.name: m.value for m in DeliveryStatus},
            {
                "SENT": "sent",
                "FAILED": "failed",
            },
        )
        self.assertEqual(
            {m.name: m.value for m in ReportFormat},
            {
                "PDF": "pdf",
                "WORD": "word",
                "JSON": "json",
            },
        )

    def test_severity_weight_label_and_normalize(self) -> None:
        self.assertEqual(Severity.LOW.weight, 1)
        self.assertEqual(Severity.MEDIUM.weight, 2)
        self.assertEqual(Severity.HIGH.weight, 3)
        self.assertEqual(Severity.CRITICAL.weight, 4)

        self.assertEqual(Severity.LOW.label, "Низкий")
        self.assertEqual(Severity.MEDIUM.label, "Средний")
        self.assertEqual(Severity.HIGH.label, "Высокий")
        self.assertEqual(Severity.CRITICAL.label, "Критический")

        cases = [
            ("low", Severity.LOW),
            ("LOW", Severity.LOW),
            ("низкий", Severity.LOW),
            ("Низкая", Severity.LOW),
            ("medium", Severity.MEDIUM),
            ("средний", Severity.MEDIUM),
            ("Средняя", Severity.MEDIUM),
            ("high", Severity.HIGH),
            ("Высокий", Severity.HIGH),
            ("высокая", Severity.HIGH),
            ("critical", Severity.CRITICAL),
            ("CRITICAL", Severity.CRITICAL),
            ("Критический", Severity.CRITICAL),
            ("критическая", Severity.CRITICAL),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertIs(Severity.normalize(raw), expected)

        for invalid in ("", "unknown", "extreme"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    Severity.normalize(invalid)

    def test_incident_type_normalize_aliases_and_fallback(self) -> None:
        cases = [
            ("phishing", IncidentType.PHISHING),
            ("Фишинг", IncidentType.PHISHING),
            ("virus", IncidentType.VIRUS),
            ("  ViRuS  ", IncidentType.VIRUS),
            ("malware", IncidentType.VIRUS),
            ("Вирус / Вредоносное ПО", IncidentType.VIRUS),
            ("bruteforce", IncidentType.BRUTEFORCE),
            ("brute-force", IncidentType.BRUTEFORCE),
            ("Подбор пароля", IncidentType.BRUTEFORCE),
            ("data_leak", IncidentType.DATA_LEAK),
            ("data-leak", IncidentType.DATA_LEAK),
            ("Утечка ПДн", IncidentType.DATA_LEAK),
            ("payment_fraud", IncidentType.PAYMENT_FRAUD),
            ("Обман с платежами", IncidentType.PAYMENT_FRAUD),
            ("unauthorized_access", IncidentType.UNAUTHORIZED_ACCESS),
            ("Несанкционированный доступ", IncidentType.UNAUTHORIZED_ACCESS),
            ("cve", IncidentType.CVE),
            ("CVE", IncidentType.CVE),
            ("Уязвимость (CVE)", IncidentType.CVE),
            ("other", IncidentType.OTHER),
            ("Прочее", IncidentType.OTHER),
            ("", IncidentType.OTHER),
            ("Сбой / Доступность", IncidentType.OTHER),
            ("unrecognized_category", IncidentType.OTHER),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertIs(IncidentType.normalize(raw), expected)

    def test_pdn_flag_from_bool_int(self) -> None:
        self.assertIs(PdnFlag.from_bool_int(True), PdnFlag.YES)
        self.assertIs(PdnFlag.from_bool_int(1), PdnFlag.YES)
        self.assertIs(PdnFlag.from_bool_int(False), PdnFlag.NO)
        self.assertIs(PdnFlag.from_bool_int(0), PdnFlag.NO)
        self.assertIs(PdnFlag.from_bool_int(None), PdnFlag.UNKNOWN)
        self.assertIs(PdnFlag.from_bool_int(PdnFlag.YES), PdnFlag.YES)
        self.assertEqual(PdnFlag.YES.to_bool_int(), 1)
        self.assertEqual(PdnFlag.NO.to_bool_int(), 0)
        self.assertEqual(PdnFlag.UNKNOWN.to_bool_int(), 0)

    def test_task_status_is_done_and_source_normalize(self) -> None:
        for done_val in ("Выполнена", "выполнена", "завершена", "закрыта", "done", TaskStatus.DONE):
            with self.subTest(done_val=done_val):
                self.assertTrue(TaskStatus.is_done(done_val))
        self.assertTrue({"выполнена", "завершена", "закрыта", "done"}.issubset(DONE_TASK_STATUSES))

        for not_done in (TaskStatus.OPEN, TaskStatus.OVERDUE, "Открыта", "Просрочена", "", None):
            with self.subTest(not_done=not_done):
                self.assertFalse(TaskStatus.is_done(not_done))

        self.assertIs(SourceType.normalize("antivirus"), SourceType.KASPERSKY)
        self.assertIs(SourceType.normalize("Kaspersky Endpoint Security"), SourceType.KASPERSKY)
        self.assertIs(SourceType.normalize("Zabbix"), SourceType.ZABBIX)
        self.assertIs(SourceType.normalize("Почта"), SourceType.EMAIL)
        self.assertIs(SourceType.normalize("Telegram"), SourceType.TELEGRAM)
        self.assertIs(SourceType.normalize("unknown_src"), SourceType.MANUAL)


class TestApiEndpointsWithIncidentEnums(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self._prev_db_path = os.environ.get("DB_PATH")
        os.environ["DB_PATH"] = str(Path(self._tmp_dir.name) / "test_incident_enums.db")
        self._client_cm = TestClient(app)
        self.client = self._client_cm.__enter__()

    def tearDown(self) -> None:
        self._client_cm.__exit__(None, None, None)
        if self._prev_db_path is None:
            os.environ.pop("DB_PATH", None)
        else:
            os.environ["DB_PATH"] = self._prev_db_path
        self._tmp_dir.cleanup()

    def _login(self, username: str) -> dict[str, str]:
        resp = self.client.post("/api/auth/login", json={"username": username, "password": "password123"})
        self.assertEqual(resp.status_code, 200, resp.text)
        return {"Authorization": f"Bearer {resp.json()['token']}"}

    def test_seeded_incidents_and_create_update_status_aliases(self) -> None:
        ib_hdr = self._login("ib")

        listed = self.client.get("/api/incidents", headers=ib_hdr)
        self.assertEqual(listed.status_code, 200)
        by_id = {inc["id"]: inc for inc in listed.json()}
        self.assertEqual(by_id[1]["incident_type"], IncidentType.VIRUS.value)
        self.assertEqual(by_id[1]["severity"], Severity.HIGH.value)
        self.assertEqual(by_id[1]["status"], IncidentStatus.NEW.value)
        self.assertEqual(by_id[1]["source"], SourceType.KASPERSKY.value)
        self.assertEqual(by_id[3]["outcome"], CheckResult.FALSE_POSITIVE.value)

        created = self.client.post(
            "/api/incidents",
            json={
                "title": "Обнаружен вирус на сервере",
                "description": "Срабатывание антивируса на SRV-APP-01",
                "incident_type": "virus",
                "severity": "Высокий",
                "source": "kaspersky",
                "computer": "SRV-APP-01",
                "has_personal_data": 0,
            },
            headers=ib_hdr,
        )
        self.assertEqual(created.status_code, 200, created.text)
        inc = created.json()
        inc_id = inc["id"]
        self.assertEqual(inc["incident_type"], IncidentType.VIRUS.value)
        self.assertEqual(inc["severity"], Severity.HIGH.value)
        self.assertEqual(inc["status"], IncidentStatus.NEW.value)
        self.assertEqual(inc["source"], SourceType.KASPERSKY.value)
        self.assertEqual(inc["instruction_id"], 1)

        filtered = self.client.get(
            "/api/incidents",
            params={"incident_type": "virus", "status": "new"},
            headers=ib_hdr,
        )
        self.assertEqual(filtered.status_code, 200)
        self.assertIn(inc_id, {item["id"] for item in filtered.json()})

        patched = self.client.patch(
            f"/api/incidents/{inc_id}",
            json={"incident_type": "cve", "severity": "Критический"},
            headers=ib_hdr,
        )
        self.assertEqual(patched.status_code, 200, patched.text)
        self.assertEqual(patched.json()["incident_type"], IncidentType.CVE.value)
        self.assertEqual(patched.json()["severity"], Severity.CRITICAL.value)

        to_work = self.client.post(
            f"/api/incidents/{inc_id}/status",
            json={"status": "in_progress"},
            headers=ib_hdr,
        )
        self.assertEqual(to_work.status_code, 200, to_work.text)
        self.assertEqual(to_work.json()["status"], IncidentStatus.IN_PROGRESS.value)
        self.assertIsNotNone(to_work.json()["taken_at"])

        to_closed = self.client.post(
            f"/api/incidents/{inc_id}/status",
            json={"status": IncidentStatus.CLOSED.value, "outcome": "resolved"},
            headers=ib_hdr,
        )
        self.assertEqual(to_closed.status_code, 200, to_closed.text)
        self.assertEqual(to_closed.json()["status"], IncidentStatus.CLOSED.value)
        self.assertEqual(to_closed.json()["outcome"], CheckResult.RESOLVED.value)
        self.assertIsNotNone(to_closed.json()["closed_at"])

        # Frontend-compatible custom outcome string should still be accepted
        custom_close = self.client.post(
            "/api/incidents/1/status",
            json={"status": "Закрыт", "outcome": "Передано в СК/РКН"},
            headers=ib_hdr,
        )
        self.assertEqual(custom_close.status_code, 200, custom_close.text)
        self.assertEqual(custom_close.json()["outcome"], "Передано в СК/РКН")

    def test_signals_and_tasks_use_enums(self) -> None:
        ib_hdr = self._login("ib")

        sig = self.client.post(
            "/api/signals",
            json={
                "source": "Kaspersky Endpoint Security",
                "sender": "ksc@corp.local",
                "body": "Brute force SSH attempts",
                "computer": "SRV-SSH-01",
                "incident_type": "bruteforce",
                "severity": "HIGH",
                "incident_key": "ssh-bf-01",
                "has_personal_data": False,
            },
        )
        self.assertEqual(sig.status_code, 200, sig.text)
        inc_id = sig.json()["incident_id"]

        card = self.client.get(f"/api/incidents/{inc_id}", headers=ib_hdr).json()
        self.assertEqual(card["incident_type"], IncidentType.BRUTEFORCE.value)
        self.assertEqual(card["severity"], Severity.HIGH.value)
        self.assertEqual(card["status"], IncidentStatus.NEW.value)
        self.assertEqual(card["source"], SourceType.KASPERSKY.value)

        # Simulator preset unknown Russian incident type falls back to OTHER
        zabbix_sig = self.client.post(
            "/api/signals",
            json={
                "source": "Zabbix",
                "body": "High CPU",
                "computer": "SRV-DB-01",
                "incident_type": "Сбой / Доступность",
                "severity": "critical",
            },
        )
        self.assertEqual(zabbix_sig.status_code, 200, zabbix_sig.text)
        z_card = self.client.get(f"/api/incidents/{zabbix_sig.json()['incident_id']}", headers=ib_hdr).json()
        self.assertEqual(z_card["incident_type"], IncidentType.OTHER.value)
        self.assertEqual(z_card["source"], SourceType.ZABBIX.value)

        sys_id = self.client.get("/api/auth/me", headers=self._login("sysadmin")).json()["id"]
        task_resp = self.client.post(
            f"/api/incidents/{inc_id}/tasks",
            json={
                "title": "Проверить SSH логи",
                "description": "Собрать и проанализировать auth.log на SRV-SSH-01",
                "assigned_to": sys_id,
                "due_date": "2026-11-30T12:00:00+00:00",
            },
            headers=ib_hdr,
        )
        self.assertEqual(task_resp.status_code, 200, task_resp.text)
        task_id = task_resp.json()["id"]
        self.assertEqual(task_resp.json()["status"], TaskStatus.OPEN.value)

        open_tasks = self.client.get("/api/tasks", params={"status": "open"}, headers=ib_hdr)
        self.assertEqual(open_tasks.status_code, 200)
        self.assertIn(task_id, {t["id"] for t in open_tasks.json()})

        done_resp = self.client.patch(
            f"/api/tasks/{task_id}",
            json={"status": "done", "result": "IP заблокирован"},
            headers=ib_hdr,
        )
        self.assertEqual(done_resp.status_code, 200, done_resp.text)
        self.assertEqual(done_resp.json()["status"], TaskStatus.DONE.value)
        self.assertIsNotNone(done_resp.json()["completed_at"])

        reopen_resp = self.client.patch(
            f"/api/tasks/{task_id}",
            json={"status": TaskStatus.OVERDUE.value},
            headers=ib_hdr,
        )
        self.assertEqual(reopen_resp.status_code, 200, reopen_resp.text)
        self.assertEqual(reopen_resp.json()["status"], TaskStatus.OVERDUE.value)
        self.assertIsNone(reopen_resp.json()["completed_at"])


if __name__ == "__main__":
    unittest.main()
