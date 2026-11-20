import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.container import AppContainer
from app.enums import CheckResult, IncidentStatus, IncidentType, SourceType, TaskStatus
from app.services.exceptions import NotFoundError, ValidationError
from main import app


class TestRequiredFieldsHttp(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self._prev_db_path = os.environ.get("DB_PATH")
        os.environ["DB_PATH"] = str(Path(self._tmp_dir.name) / "test_required_fields_http.db")
        self._client_cm = TestClient(app)
        self.client = self._client_cm.__enter__()

        self.ib_hdr = self._login("ib")
        self.sys_hdr = self._login("sysadmin")
        self.sys_id = self.client.get("/api/auth/me", headers=self.sys_hdr).json()["id"]

    def tearDown(self) -> None:
        self._client_cm.__exit__(None, None, None)
        if self._prev_db_path is None:
            os.environ.pop("DB_PATH", None)
        else:
            os.environ["DB_PATH"] = self._prev_db_path
        self._tmp_dir.cleanup()

    def _login(self, username: str) -> dict[str, str]:
        resp = self.client.post(
            "/api/auth/login",
            json={"username": username, "password": "password123"},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        return {"Authorization": f"Bearer {resp.json()['token']}"}

    def _valid_task_payload(self) -> dict[str, Any]:
        return {
            "title": "Проверить рабочую станцию",
            "description": "Выполнить полную антивирусную проверку",
            "assigned_to": self.sys_id,
            "due_date": "2026-12-01T15:30:00+00:00",
        }

    def _valid_incident_payload(self) -> dict[str, Any]:
        return {
            "title": "Подозрительное письмо",
            "description": "Сотрудник получил фишинговое письмо с вложением",
            "incident_type": "phishing",
            "source": "mail_gateway",
            "severity": "medium",
            "has_personal_data": 0,
        }

    def test_task_create_validation(self) -> None:
        base = self._valid_task_payload()

        invalid_cases: list[tuple[str, dict[str, Any], int]] = [
            ("missing_title", {k: v for k, v in base.items() if k != "title"}, 422),
            ("none_title", {**base, "title": None}, 422),
            ("empty_title", {**base, "title": ""}, 422),
            ("blank_title", {**base, "title": "   \t\n "}, 422),
            ("missing_description", {k: v for k, v in base.items() if k != "description"}, 422),
            ("none_description", {**base, "description": None}, 422),
            ("empty_description", {**base, "description": ""}, 422),
            ("blank_description", {**base, "description": "   "}, 422),
            ("missing_assigned_to", {k: v for k, v in base.items() if k != "assigned_to"}, 422),
            ("none_assigned_to", {**base, "assigned_to": None}, 422),
            ("str_assigned_to", {**base, "assigned_to": "abc"}, 422),
            ("numeric_str_assigned_to", {**base, "assigned_to": str(self.sys_id)}, 422),
            ("bool_assigned_to", {**base, "assigned_to": True}, 422),
            ("zero_assigned_to", {**base, "assigned_to": 0}, 422),
            ("negative_assigned_to", {**base, "assigned_to": -1}, 422),
            ("float_assigned_to", {**base, "assigned_to": 1.5}, 422),
            ("nonexistent_assigned_to", {**base, "assigned_to": 999999}, 404),
            ("missing_due_date", {k: v for k, v in base.items() if k != "due_date"}, 422),
            ("none_due_date", {**base, "due_date": None}, 422),
            ("empty_due_date", {**base, "due_date": ""}, 422),
            ("blank_due_date", {**base, "due_date": "   "}, 422),
            ("invalid_due_date_text", {**base, "due_date": "not-a-date"}, 422),
            ("invalid_due_date_month", {**base, "due_date": "2026-13-01T00:00:00Z"}, 422),
            ("invalid_due_date_ru", {**base, "due_date": "01.12.2026"}, 422),
            ("invalid_due_date_int", {**base, "due_date": 123456}, 422),
        ]
        for label, payload, expected_status in invalid_cases:
            with self.subTest(case=label):
                resp = self.client.post("/api/incidents/1/tasks", json=payload, headers=self.ib_hdr)
                self.assertEqual(resp.status_code, expected_status, resp.text)

        for valid_due in (
            "2026-12-01T15:30:00+00:00",
            "2026-12-01T15:30:00Z",
            "2026-12-01T15:30:00",
        ):
            with self.subTest(valid_due=valid_due):
                ok = self.client.post(
                    "/api/incidents/1/tasks",
                    json={**base, "title": "  Задача  ", "description": "  Описание  ", "due_date": valid_due},
                    headers=self.ib_hdr,
                )
                self.assertEqual(ok.status_code, 200, ok.text)
                body = ok.json()
                self.assertEqual(body["title"], "Задача")
                self.assertEqual(body["description"], "Описание")
                self.assertEqual(body["assigned_to"], self.sys_id)
                self.assertEqual(body["due_date"], valid_due)

    def test_task_update_done_requires_non_blank_result(self) -> None:
        t_resp = self.client.post(
            "/api/incidents/1/tasks",
            json=self._valid_task_payload(),
            headers=self.ib_hdr,
        )
        self.assertEqual(t_resp.status_code, 200, t_resp.text)
        task_id = t_resp.json()["id"]

        for done_status in ("Выполнена", "done", "завершена", "закрыта"):
            with self.subTest(done_status=done_status, kind="missing_result"):
                resp = self.client.patch(
                    f"/api/tasks/{task_id}",
                    json={"status": done_status},
                    headers=self.sys_hdr,
                )
                self.assertEqual(resp.status_code, 400, resp.text)

            with self.subTest(done_status=done_status, kind="none_result"):
                resp = self.client.patch(
                    f"/api/tasks/{task_id}",
                    json={"status": done_status, "result": None},
                    headers=self.sys_hdr,
                )
                self.assertEqual(resp.status_code, 400, resp.text)

            for blank in ("", "   \t"):
                with self.subTest(done_status=done_status, blank=repr(blank)):
                    resp = self.client.patch(
                        f"/api/tasks/{task_id}",
                        json={"status": done_status, "result": blank},
                        headers=self.sys_hdr,
                    )
                    self.assertEqual(resp.status_code, 422, resp.text)

        # Non-done status without result is permitted
        open_resp = self.client.patch(
            f"/api/tasks/{task_id}",
            json={"status": TaskStatus.OVERDUE.value, "result": ""},
            headers=self.sys_hdr,
        )
        self.assertEqual(open_resp.status_code, 200, open_resp.text)

        # Pre-populate non-blank result while still open, then complete without re-sending result
        set_res = self.client.patch(
            f"/api/tasks/{task_id}",
            json={"status": TaskStatus.OPEN.value, "result": "Вложение удалено"},
            headers=self.sys_hdr,
        )
        self.assertEqual(set_res.status_code, 200, set_res.text)

        # Explicitly sending blank result when transitioning to done still fails even if task has result
        blank_override = self.client.patch(
            f"/api/tasks/{task_id}",
            json={"status": "done", "result": "   "},
            headers=self.sys_hdr,
        )
        self.assertEqual(blank_override.status_code, 422, blank_override.text)

        # Transitioning to done without result succeeds when task already has non-blank result
        done_existing = self.client.patch(
            f"/api/tasks/{task_id}",
            json={"status": "done"},
            headers=self.sys_hdr,
        )
        self.assertEqual(done_existing.status_code, 200, done_existing.text)
        self.assertEqual(done_existing.json()["status"], TaskStatus.DONE.value)
        self.assertEqual(done_existing.json()["result"], "Вложение удалено")
        self.assertIsNotNone(done_existing.json()["completed_at"])

        # Fresh task completed directly with result in payload succeeds
        t2_id = self.client.post(
            "/api/incidents/1/tasks",
            json=self._valid_task_payload(),
            headers=self.ib_hdr,
        ).json()["id"]
        done_direct = self.client.patch(
            f"/api/tasks/{t2_id}",
            json={"status": "Выполнена", "result": "  Очищено  "},
            headers=self.sys_hdr,
        )
        self.assertEqual(done_direct.status_code, 200, done_direct.text)
        self.assertEqual(done_direct.json()["result"], "Очищено")

    def test_incident_create_validation(self) -> None:
        base = self._valid_incident_payload()

        for field in ("title", "description", "incident_type", "source"):
            for case_name, mutator in (
                ("missing", lambda d, f=field: {k: v for k, v in d.items() if k != f}),
                ("none", lambda d, f=field: {**d, f: None}),
                ("empty", lambda d, f=field: {**d, f: ""}),
                ("whitespace", lambda d, f=field: {**d, f: "   \n\t "}),
            ):
                with self.subTest(field=field, case=case_name):
                    resp = self.client.post("/api/incidents", json=mutator(base), headers=self.ib_hdr)
                    self.assertEqual(resp.status_code, 422, resp.text)

        ok = self.client.post("/api/incidents", json=base, headers=self.ib_hdr)
        self.assertEqual(ok.status_code, 200, ok.text)
        created = ok.json()
        self.assertEqual(created["incident_type"], IncidentType.PHISHING.value)
        self.assertEqual(created["source"], SourceType.EMAIL.value)

    def test_incident_close_requires_non_blank_outcome(self) -> None:
        inc_id = self.client.post(
            "/api/incidents",
            json=self._valid_incident_payload(),
            headers=self.ib_hdr,
        ).json()["id"]

        for closed_status in ("Закрыт", "closed", "close"):
            with self.subTest(closed_status=closed_status, kind="missing_outcome"):
                resp = self.client.post(
                    f"/api/incidents/{inc_id}/status",
                    json={"status": closed_status},
                    headers=self.ib_hdr,
                )
                self.assertEqual(resp.status_code, 400, resp.text)

            with self.subTest(closed_status=closed_status, kind="none_outcome"):
                resp = self.client.post(
                    f"/api/incidents/{inc_id}/status",
                    json={"status": closed_status, "outcome": None},
                    headers=self.ib_hdr,
                )
                self.assertEqual(resp.status_code, 400, resp.text)

            for blank in ("", "   "):
                with self.subTest(closed_status=closed_status, blank=repr(blank)):
                    resp = self.client.post(
                        f"/api/incidents/{inc_id}/status",
                        json={"status": closed_status, "outcome": blank},
                        headers=self.ib_hdr,
                    )
                    self.assertEqual(resp.status_code, 422, resp.text)

        # Non-closed transition does not require outcome
        in_review = self.client.post(
            f"/api/incidents/{inc_id}/status",
            json={"status": IncidentStatus.IN_REVIEW.value, "outcome": "resolved"},
            headers=self.ib_hdr,
        )
        self.assertEqual(in_review.status_code, 200, in_review.text)

        # Explicitly blank outcome still rejected even if incident already has outcome
        blank_close = self.client.post(
            f"/api/incidents/{inc_id}/status",
            json={"status": "Закрыт", "outcome": "   "},
            headers=self.ib_hdr,
        )
        self.assertEqual(blank_close.status_code, 422, blank_close.text)

        # Closing without outcome succeeds when incident already has non-blank outcome
        close_with_existing = self.client.post(
            f"/api/incidents/{inc_id}/status",
            json={"status": "Закрыт"},
            headers=self.ib_hdr,
        )
        self.assertEqual(close_with_existing.status_code, 200, close_with_existing.text)
        self.assertEqual(close_with_existing.json()["status"], IncidentStatus.CLOSED.value)
        self.assertEqual(close_with_existing.json()["outcome"], CheckResult.RESOLVED.value)
        self.assertIsNotNone(close_with_existing.json()["closed_at"])

        # Closing with outcome in payload succeeds on a fresh incident
        inc2_id = self.client.post(
            "/api/incidents",
            json=self._valid_incident_payload(),
            headers=self.ib_hdr,
        ).json()["id"]
        close_with_payload = self.client.post(
            f"/api/incidents/{inc2_id}/status",
            json={"status": "Закрыт", "outcome": "Ложное срабатывание"},
            headers=self.ib_hdr,
        )
        self.assertEqual(close_with_payload.status_code, 200, close_with_payload.text)
        self.assertEqual(close_with_payload.json()["outcome"], CheckResult.FALSE_POSITIVE.value)

    def test_signal_in_keeps_minimal_body_only_compatibility(self) -> None:
        for bad_payload in ({}, {"body": None}, {"body": ""}, {"body": "   \t\n"}):
            with self.subTest(bad_payload=bad_payload):
                resp = self.client.post("/api/signals", json=bad_payload)
                self.assertEqual(resp.status_code, 422, resp.text)

        ok = self.client.post("/api/signals", json={"body": "Минимальный внешний сигнал"})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertFalse(ok.json()["deduplicated"])


class TestRequiredFieldsService(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._tmp_dir.name) / "test_required_fields_svc.db")
        self.container = AppContainer(db_path=self.db_path)
        self.container.init_db()

        ib = self.container.user_repo.get_by_username("ib")
        sysadmin = self.container.user_repo.get_by_username("sysadmin")
        assert ib is not None and sysadmin is not None
        self.ib = ib
        self.sysadmin = sysadmin

    def tearDown(self) -> None:
        self._tmp_dir.cleanup()

    def test_task_service_create_validation(self) -> None:
        task_svc = self.container.task_service
        base = {
            "title": "Проверить хост",
            "description": "Собрать логи и изолировать хост",
            "assigned_to": self.sysadmin.id,
            "due_date": "2026-12-01T10:00:00+00:00",
        }

        invalid_payloads = [
            {k: v for k, v in base.items() if k != "title"},
            {**base, "title": "   "},
            {**base, "title": None},
            {k: v for k, v in base.items() if k != "description"},
            {**base, "description": ""},
            {**base, "description": "  \t "},
            {k: v for k, v in base.items() if k != "assigned_to"},
            {**base, "assigned_to": None},
            {**base, "assigned_to": True},
            {**base, "assigned_to": str(self.sysadmin.id)},
            {**base, "assigned_to": 0},
            {**base, "assigned_to": 999999},
            {k: v for k, v in base.items() if k != "due_date"},
            {**base, "due_date": None},
            {**base, "due_date": "   "},
            {**base, "due_date": "invalid-iso"},
        ]
        for bad in invalid_payloads:
            with self.subTest(bad=bad):
                expected_exc = (
                    NotFoundError
                    if bad.get("assigned_to") == 999999
                    else ValidationError
                )
                with self.assertRaises(expected_exc):
                    task_svc.create_task(self.ib, 1, bad)

        created = task_svc.create_task(self.ib, 1, base)
        self.assertEqual(created["assigned_to"], self.sysadmin.id)
        self.assertEqual(created["due_date"], base["due_date"])

    def test_task_service_update_done_validation(self) -> None:
        task_svc = self.container.task_service
        created = task_svc.create_task(
            self.ib,
            1,
            {
                "title": "Проверить логи",
                "description": "Собрать журналы событий",
                "assigned_to": self.sysadmin.id,
                "due_date": "2026-12-01T10:00:00+00:00",
            },
        )
        task_id = created["id"]

        for bad_done in (
            {"status": TaskStatus.DONE},
            {"status": "done", "result": None},
            {"status": "завершена", "result": ""},
            {"status": "Выполнена", "result": "   "},
        ):
            with self.subTest(bad_done=bad_done):
                with self.assertRaises(ValidationError):
                    task_svc.update_task(self.sysadmin, task_id, bad_done)

        task_svc.update_task(self.sysadmin, task_id, {"result": "Инцидент локализован"})
        with self.assertRaises(ValidationError):
            task_svc.update_task(self.sysadmin, task_id, {"status": "done", "result": "  "})

        done = task_svc.update_task(self.sysadmin, task_id, {"status": TaskStatus.DONE})
        self.assertEqual(done["status"], TaskStatus.DONE.value)
        self.assertEqual(done["result"], "Инцидент локализован")

        # Cannot blank result while task remains done
        with self.assertRaises(ValidationError):
            task_svc.update_task(self.sysadmin, task_id, {"result": "   "})

    def test_incident_service_create_and_close_validation(self) -> None:
        inc_svc = self.container.incident_service
        base = {
            "title": "Неавторизованный вход",
            "description": "Множественные неудачные попытки входа",
            "incident_type": "bruteforce",
            "source": "zabbix",
            "severity": "high",
        }

        for field in ("title", "description", "incident_type", "source"):
            for bad_val in (None, "", "   "):
                payload = {**base, field: bad_val}
                with self.subTest(field=field, bad_val=bad_val):
                    with self.assertRaises(ValidationError):
                        inc_svc.create_incident(self.ib, payload)

            omitted = {k: v for k, v in base.items() if k != field}
            with self.subTest(field=field, bad_val="OMITTED"):
                with self.assertRaises(ValidationError):
                    inc_svc.create_incident(self.ib, omitted)

        inc = inc_svc.create_incident(self.ib, base)
        inc_id = inc["id"]
        self.assertEqual(inc["incident_type"], IncidentType.BRUTEFORCE.value)
        self.assertEqual(inc["source"], SourceType.ZABBIX.value)

        for bad_outcome in (None, "", "   "):
            with self.subTest(bad_outcome=bad_outcome):
                with self.assertRaises(ValidationError):
                    inc_svc.change_status(self.ib, inc_id, IncidentStatus.CLOSED, outcome=bad_outcome)

        inc_svc.change_status(
            self.ib,
            inc_id,
            IncidentStatus.IN_REVIEW,
            outcome="Инцидент подтверждён",
        )
        with self.assertRaises(ValidationError):
            inc_svc.change_status(self.ib, inc_id, IncidentStatus.CLOSED, outcome="   ")

        closed = inc_svc.change_status(self.ib, inc_id, IncidentStatus.CLOSED)
        self.assertEqual(closed["status"], IncidentStatus.CLOSED.value)
        self.assertEqual(closed["outcome"], CheckResult.CONFIRMED.value)

        # Direct signal ingestion still works with only body
        sig = self.container.ingestion_service.receive({"body": "Сигнал только с телом"})
        self.assertFalse(sig["deduplicated"])
        with self.assertRaises(ValidationError):
            self.container.ingestion_service.receive({"body": "   "})


if __name__ == "__main__":
    unittest.main()
