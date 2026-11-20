import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.container import AppContainer, container
from app.domain.models import Incident, User
from app.enums import IncidentStatus, IncidentType, Role, Severity
from main import app


class TestAccessControlServiceLawyer(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._tmp_dir.name) / "lawyer_access.db")
        self.container = AppContainer(db_path=self.db_path)
        self.container.init_db()

        self.ib = self.container.user_repo.get_by_username("ib")
        self.sysadmin = self.container.user_repo.get_by_username("sysadmin")
        self.it_head = self.container.user_repo.get_by_username("it_head")
        self.lawyer = self.container.user_repo.get_by_username("lawyer")
        assert self.ib and self.sysadmin and self.it_head and self.lawyer

        self.access = self.container.access_service
        self.tech_inc = Incident(id=10, computer="SRV-01", employee="", has_personal_data=0)
        self.emp_inc = Incident(id=11, computer="WS-02", employee="Иванов И.И.", has_personal_data=0)
        self.pdn_inc = Incident(id=12, computer="CRM-01", employee="Волков И.П.", has_personal_data=1)
        self.stale_non_pdn = Incident(
            id=13,
            computer="WS-03",
            employee="",
            has_personal_data=0,
            access_category="personal_data",
        )
        self.inactive_lawyer = User(
            id=999,
            username="inactive_lawyer",
            full_name="Бывший юрист",
            role=Role.LAWYER,
            active=False,
        )

    def tearDown(self) -> None:
        self._tmp_dir.cleanup()

    def test_lawyer_service_level_permissions_matrix(self) -> None:
        # View permissions: lawyer sees ONLY PDn incidents
        self.assertTrue(self.access.can_view(self.lawyer, self.pdn_inc))
        self.assertFalse(self.access.can_view(self.lawyer, self.tech_inc))
        self.assertFalse(self.access.can_view(self.lawyer, self.emp_inc))
        self.assertFalse(self.access.can_view(self.lawyer, self.stale_non_pdn))
        self.assertFalse(self.access.can_view(self.inactive_lawyer, self.pdn_inc))

        # Edit permissions: lawyer only on PDn and only legal fields
        self.assertTrue(self.access.can_edit(self.lawyer, self.pdn_inc))
        self.assertFalse(self.access.can_edit(self.lawyer, self.tech_inc))
        self.assertFalse(self.access.can_edit(self.lawyer, self.emp_inc))
        self.assertTrue(
            self.access.can_edit_incident_fields(
                self.lawyer, self.pdn_inc, ["rkn_draft", "has_personal_data"]
            )
        )
        for op_field in ("title", "description", "severity", "incident_type", "instruction_id"):
            with self.subTest(op_field=op_field):
                self.assertFalse(
                    self.access.can_edit_incident_fields(self.lawyer, self.pdn_inc, [op_field])
                )
        self.assertFalse(
            self.access.can_edit_incident_fields(
                self.lawyer, self.pdn_inc, ["rkn_draft", "severity"]
            )
        )

        # Creation, operational actions, and tasks are forbidden for lawyer
        self.assertFalse(self.access.can_create_incident(self.lawyer, has_personal_data=False))
        self.assertFalse(self.access.can_create_incident(self.lawyer, has_personal_data=True))
        self.assertFalse(self.access.can_create_pdn(self.lawyer))
        self.assertTrue(self.access.can_view_pdn(self.lawyer))
        self.assertTrue(self.access.can_mark_pdn(self.lawyer))
        self.assertFalse(self.access.can_edit_operational(self.lawyer))
        self.assertFalse(self.access.can_access_tasks(self.lawyer))
        self.assertTrue(self.access.can_access_rkn(self.lawyer))

        # Comparison roles
        self.assertTrue(self.access.can_edit_operational(self.ib))
        self.assertTrue(self.access.can_edit_operational(self.it_head))
        self.assertTrue(self.access.can_edit_operational(self.sysadmin))
        self.assertTrue(self.access.can_create_incident(self.ib, has_personal_data=True))
        self.assertTrue(self.access.can_create_incident(self.it_head, has_personal_data=True))
        self.assertTrue(self.access.can_create_incident(self.sysadmin, has_personal_data=False))
        self.assertFalse(self.access.can_create_incident(self.sysadmin, has_personal_data=True))
        self.assertFalse(self.access.can_access_rkn(self.sysadmin))
        self.assertTrue(self.access.can_access_tasks(self.sysadmin))


class TestLawyerRbacApiMatrix(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self._prev_db_path = os.environ.get("DB_PATH")
        os.environ["DB_PATH"] = str(Path(self._tmp_dir.name) / "test_lawyer_rbac.db")
        self._client_cm = TestClient(app)
        self.client = self._client_cm.__enter__()

        self.ib_hdr, self.ib_user = self._login("ib")
        self.sys_hdr, self.sys_user = self._login("sysadmin")
        self.head_hdr, self.head_user = self._login("it_head")
        self.lawyer_hdr, self.lawyer_user = self._login("lawyer")

        # Create a purely TECHNICAL non-PDn incident (employee="", has_personal_data=0)
        tech_resp = self.client.post(
            "/api/incidents",
            json={
                "title": "Скан портов на шлюзе",
                "description": "Сетевая активность",
                "incident_type": IncidentType.UNAUTHORIZED_ACCESS.value,
                "severity": Severity.MEDIUM.value,
                "computer": "GW-01",
                "employee": "",
                "source": "manual",
                "has_personal_data": 0,
            },
            headers=self.ib_hdr,
        )
        self.assertEqual(tech_resp.status_code, 200, tech_resp.text)
        self.tech_inc_id = tech_resp.json()["id"]

        # Create a second PDn incident so we can test toggling has_personal_data=0 cleanly
        pdn2_resp = self.client.post(
            "/api/incidents",
            json={
                "title": "Утечка анкет кандидатов",
                "description": "Подозрительная отправка по почте",
                "incident_type": IncidentType.DATA_LEAK.value,
                "severity": Severity.HIGH.value,
                "computer": "HR-PC-01",
                "employee": "Орлова Н.В.",
                "source": "manual",
                "has_personal_data": 1,
            },
            headers=self.ib_hdr,
        )
        self.assertEqual(pdn2_resp.status_code, 200, pdn2_resp.text)
        self.pdn2_inc_id = pdn2_resp.json()["id"]

        # Create tasks on both non-PDn and PDn incidents
        t_tech = self.client.post(
            f"/api/incidents/{self.tech_inc_id}/tasks",
            json={
                "title": "Проверить правила firewall",
                "description": "Проверить правила на шлюзе",
                "assigned_to": self.sys_user["id"],
                "due_date": "2026-12-01T12:00:00+00:00",
            },
            headers=self.ib_hdr,
        )
        self.assertEqual(t_tech.status_code, 200, t_tech.text)
        self.tech_task_id = t_tech.json()["id"]

        t_pdn = self.client.post(
            "/api/incidents/2/tasks",
            json={
                "title": "Заблокировать выгрузку CRM",
                "description": "Ограничить экспорт из CRM",
                "assigned_to": self.sys_user["id"],
                "due_date": "2026-12-01T12:00:00+00:00",
            },
            headers=self.ib_hdr,
        )
        self.assertEqual(t_pdn.status_code, 200, t_pdn.text)
        self.pdn_task_id = t_pdn.json()["id"]

    def tearDown(self) -> None:
        self._client_cm.__exit__(None, None, None)
        if self._prev_db_path is None:
            os.environ.pop("DB_PATH", None)
        else:
            os.environ["DB_PATH"] = self._prev_db_path
        self._tmp_dir.cleanup()

    def _login(self, username: str, password: str = "password123") -> tuple[dict[str, str], dict]:
        resp = self.client.post("/api/auth/login", json={"username": username, "password": password})
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        return {"Authorization": f"Bearer {body['token']}"}, body["user"]

    def _audit_tuples(self) -> list[tuple[int | None, str, int | None, str]]:
        return [
            (r.user_id, r.object_type, r.object_id, r.action)
            for r in container.audit_repo.list_recent(limit=200)
        ]

    def test_lawyer_allowed_pdn_and_legal_endpoints_with_audit(self) -> None:
        lawyer_id = self.lawyer_user["id"]

        # GET /api/incidents returns ONLY PDn incidents (has_personal_data = 1)
        listed = self.client.get("/api/incidents", headers=self.lawyer_hdr)
        self.assertEqual(listed.status_code, 200, listed.text)
        listed_items = listed.json()
        self.assertTrue(all(item["has_personal_data"] == 1 for item in listed_items))
        self.assertEqual({item["id"] for item in listed_items}, {2, self.pdn2_inc_id})

        # Filtered list also excludes non-PDn incidents
        filtered = self.client.get(
            "/api/incidents",
            params={"q": "GW-01"},
            headers=self.lawyer_hdr,
        )
        self.assertEqual(filtered.status_code, 200)
        self.assertEqual(filtered.json(), [])

        # GET /api/incidents/{id} allowed on PDn incident #2 + logs view
        card = self.client.get("/api/incidents/2", headers=self.lawyer_hdr)
        self.assertEqual(card.status_code, 200, card.text)
        self.assertEqual(card.json()["id"], 2)
        self.assertIn((lawyer_id, "incident", 2, "view"), self._audit_tuples())

        # GET / PUT / POST confirm on RKN endpoints for PDn incident #2
        rkn_get = self.client.get("/api/incidents/2/rkn", headers=self.lawyer_hdr)
        self.assertEqual(rkn_get.status_code, 200, rkn_get.text)
        self.assertTrue(rkn_get.json()["is_auto_generated"])
        self.assertIn((lawyer_id, "regulator_notice", 2, "view"), self._audit_tuples())

        rkn_put = self.client.put(
            "/api/incidents/2/rkn",
            json={"rkn_draft": "Юридически выверенный черновик РКН"},
            headers=self.lawyer_hdr,
        )
        self.assertEqual(rkn_put.status_code, 200, rkn_put.text)
        self.assertFalse(rkn_put.json()["is_auto_generated"])
        self.assertEqual(rkn_put.json()["rkn_draft"], "Юридически выверенный черновик РКН")
        self.assertIn((lawyer_id, "regulator_notice", 2, "update_draft"), self._audit_tuples())

        rkn_confirm = self.client.post(
            "/api/incidents/2/rkn/confirm",
            json={"confirmation": "RKN-REG-2026-404"},
            headers=self.lawyer_hdr,
        )
        self.assertEqual(rkn_confirm.status_code, 200, rkn_confirm.text)
        confirm_data = rkn_confirm.json()
        self.assertEqual(confirm_data["confirmation"], "RKN-REG-2026-404")
        self.assertIsNotNone(confirm_data["sent_at"])
        self.assertIn((lawyer_id, "regulator_notice", 2, "mark_sent"), self._audit_tuples())

        # Incident card reflects confirmation and history
        card_after = self.client.get("/api/incidents/2", headers=self.lawyer_hdr).json()
        self.assertEqual(card_after["rkn_confirmation"], "RKN-REG-2026-404")
        self.assertIsNotNone(card_after["rkn_sent_at"])
        self.assertIn("rkn_sent", [h["action"] for h in card_after["history"]])

        # PATCH /api/incidents/{id} allowed for legal fields (rkn_draft, has_personal_data)
        patch_draft = self.client.patch(
            "/api/incidents/2",
            json={"rkn_draft": "Финальная редакция уведомления РКН"},
            headers=self.lawyer_hdr,
        )
        self.assertEqual(patch_draft.status_code, 200, patch_draft.text)
        self.assertEqual(patch_draft.json()["rkn_draft"], "Финальная редакция уведомления РКН")
        self.assertIn((lawyer_id, "incident", 2, "update"), self._audit_tuples())

        patch_pdn_keep = self.client.patch(
            f"/api/incidents/{self.pdn2_inc_id}",
            json={"has_personal_data": 1, "rkn_draft": "ПДн подтверждены"},
            headers=self.lawyer_hdr,
        )
        self.assertEqual(patch_pdn_keep.status_code, 200, patch_pdn_keep.text)
        self.assertEqual(patch_pdn_keep.json()["has_personal_data"], 1)

        # Lawyer can reclassify PDn=0 on PDn incident, after which it becomes inaccessible (403)
        patch_pdn_clear = self.client.patch(
            f"/api/incidents/{self.pdn2_inc_id}",
            json={"has_personal_data": 0},
            headers=self.lawyer_hdr,
        )
        self.assertEqual(patch_pdn_clear.status_code, 200, patch_pdn_clear.text)
        self.assertEqual(patch_pdn_clear.json()["has_personal_data"], 0)
        self.assertEqual(
            self.client.get(f"/api/incidents/{self.pdn2_inc_id}", headers=self.lawyer_hdr).status_code,
            403,
        )

        # Auxiliary read/trigger endpoints allowed for lawyer
        self.assertEqual(
            self.client.post("/api/escalations/check", headers=self.lawyer_hdr).status_code, 200
        )
        self.assertEqual(
            self.client.get("/api/notifications", headers=self.lawyer_hdr).status_code, 200
        )
        self.assertEqual(
            self.client.get("/api/reports/monthly", headers=self.lawyer_hdr).status_code, 200
        )
        self.assertEqual(
            self.client.get("/api/instructions", headers=self.lawyer_hdr).status_code, 200
        )

    def test_lawyer_forbidden_endpoints_and_fields_with_audit(self) -> None:
        lawyer_id = self.lawyer_user["id"]
        before_card = self.client.get("/api/incidents/2", headers=self.ib_hdr).json()

        # Non-PDn access (both EMPLOYEE_INVOLVED #1 and TECHNICAL self.tech_inc_id)
        for non_pdn_id in (1, self.tech_inc_id):
            with self.subTest(non_pdn_id=non_pdn_id):
                self.assertEqual(
                    self.client.get(f"/api/incidents/{non_pdn_id}", headers=self.lawyer_hdr).status_code,
                    403,
                )
                self.assertIn((lawyer_id, "incident", non_pdn_id, "access_denied"), self._audit_tuples())

                self.assertEqual(
                    self.client.get(f"/api/incidents/{non_pdn_id}/rkn", headers=self.lawyer_hdr).status_code,
                    403,
                )
                self.assertEqual(
                    self.client.put(
                        f"/api/incidents/{non_pdn_id}/rkn",
                        json={"rkn_draft": "Запрещено"},
                        headers=self.lawyer_hdr,
                    ).status_code,
                    403,
                )
                self.assertEqual(
                    self.client.post(
                        f"/api/incidents/{non_pdn_id}/rkn/confirm",
                        json={"confirmation": "RKN-FORBIDDEN"},
                        headers=self.lawyer_hdr,
                    ).status_code,
                    403,
                )
                self.assertIn(
                    (lawyer_id, "regulator_notice", non_pdn_id, "access_denied"),
                    self._audit_tuples(),
                )
                self.assertEqual(
                    self.client.patch(
                        f"/api/incidents/{non_pdn_id}",
                        json={"rkn_draft": "Нельзя"},
                        headers=self.lawyer_hdr,
                    ).status_code,
                    403,
                )
                self.assertEqual(
                    self.client.patch(
                        f"/api/incidents/{non_pdn_id}",
                        json={"has_personal_data": 1},
                        headers=self.lawyer_hdr,
                    ).status_code,
                    403,
                )

        # Operational fields on PDn incident #2 are forbidden via PATCH
        forbidden_patches = [
            {"title": "Новое название"},
            {"description": "Новое описание"},
            {"severity": "low"},
            {"incident_type": "phishing"},
            {"instruction_id": 1},
            {"rkn_draft": "Откат из-за смешанного запроса", "severity": "low"},
        ]
        for payload in forbidden_patches:
            with self.subTest(payload=payload):
                resp = self.client.patch(
                    "/api/incidents/2",
                    json=payload,
                    headers=self.lawyer_hdr,
                )
                self.assertEqual(resp.status_code, 403, resp.text)
                self.assertIn((lawyer_id, "incident", 2, "edit_denied"), self._audit_tuples())

        after_card = self.client.get("/api/incidents/2", headers=self.ib_hdr).json()
        for field in ("title", "description", "severity", "incident_type", "instruction_id", "rkn_draft"):
            self.assertEqual(after_card[field], before_card[field])

        # Manual incident creation forbidden for lawyer (both non-PDn and PDn)
        for pd_flag in (0, 1):
            create_resp = self.client.post(
                "/api/incidents",
                json={
                    "title": "Ручной инцидент юриста",
                    "description": "Попытка создания инцидента юристом",
                    "incident_type": IncidentType.DATA_LEAK.value,
                    "source": "manual",
                    "has_personal_data": pd_flag,
                },
                headers=self.lawyer_hdr,
            )
            self.assertEqual(create_resp.status_code, 403, create_resp.text)
        self.assertIn((lawyer_id, "incident", None, "create_denied"), self._audit_tuples())

        # Operational status transitions / closing forbidden on both non-PDn and PDn
        self.assertEqual(
            self.client.post(
                "/api/incidents/1/status",
                json={"status": IncidentStatus.IN_PROGRESS.value},
                headers=self.lawyer_hdr,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/incidents/2/status",
                json={"status": IncidentStatus.CLOSED.value, "outcome": "Устранен"},
                headers=self.lawyer_hdr,
            ).status_code,
            403,
        )
        self.assertIn((lawyer_id, "incident", 2, "edit_denied"), self._audit_tuples())

        # Technical checklist steps forbidden on both non-PDn and PDn
        self.assertEqual(
            self.client.put(
                "/api/incidents/1/steps/0",
                json={"completed": True},
                headers=self.lawyer_hdr,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.put(
                "/api/incidents/2/steps/0",
                json={"completed": True},
                headers=self.lawyer_hdr,
            ).status_code,
            403,
        )

        # Sysadmin tasks forbidden: create, list, update
        self.assertEqual(
            self.client.post(
                "/api/incidents/1/tasks",
                json={
                    "title": "Задача от юриста",
                    "description": "Описание задачи",
                    "assigned_to": self.sys_user["id"],
                    "due_date": "2026-12-01T12:00:00+00:00",
                },
                headers=self.lawyer_hdr,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/incidents/2/tasks",
                json={
                    "title": "ПДн задача от юриста",
                    "description": "Описание ПДн задачи",
                    "assigned_to": self.sys_user["id"],
                    "due_date": "2026-12-01T12:00:00+00:00",
                },
                headers=self.lawyer_hdr,
            ).status_code,
            403,
        )
        self.assertIn((lawyer_id, "task", None, "create_denied"), self._audit_tuples())

        self.assertEqual(self.client.get("/api/tasks", headers=self.lawyer_hdr).status_code, 403)
        self.assertIn((lawyer_id, "task", None, "access_denied"), self._audit_tuples())

        self.assertEqual(
            self.client.patch(
                f"/api/tasks/{self.tech_task_id}",
                json={"status": "Выполнена"},
                headers=self.lawyer_hdr,
            ).status_code,
            403,
        )
        self.assertIn((lawyer_id, "task", self.tech_task_id, "edit_denied"), self._audit_tuples())

        self.assertEqual(
            self.client.patch(
                f"/api/tasks/{self.pdn_task_id}",
                json={"status": "Выполнена"},
                headers=self.lawyer_hdr,
            ).status_code,
            403,
        )
        self.assertIn((lawyer_id, "task", self.pdn_task_id, "edit_denied"), self._audit_tuples())

    def test_cross_role_comparison_sysadmin_ib_and_it_head(self) -> None:
        # Sysadmin: non-PDn operational allowed; PDn & ALL RKN endpoints forbidden (403)
        sys_incidents = self.client.get("/api/incidents", headers=self.sys_hdr)
        self.assertEqual(sys_incidents.status_code, 200)
        sys_inc_ids = {item["id"] for item in sys_incidents.json()}
        self.assertIn(1, sys_inc_ids)
        self.assertIn(self.tech_inc_id, sys_inc_ids)
        self.assertNotIn(2, sys_inc_ids)

        for inc_id in (1, 2):
            self.assertEqual(self.client.get(f"/api/incidents/{inc_id}/rkn", headers=self.sys_hdr).status_code, 403)
            self.assertEqual(
                self.client.put(
                    f"/api/incidents/{inc_id}/rkn",
                    json={"rkn_draft": "no"},
                    headers=self.sys_hdr,
                ).status_code,
                403,
            )
            self.assertEqual(
                self.client.post(
                    f"/api/incidents/{inc_id}/rkn/confirm",
                    json={"confirmation": "no"},
                    headers=self.sys_hdr,
                ).status_code,
                403,
            )

        self.assertEqual(
            self.client.post(
                f"/api/incidents/{self.tech_inc_id}/status",
                json={"status": IncidentStatus.IN_PROGRESS.value},
                headers=self.sys_hdr,
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.put(
                f"/api/incidents/{self.tech_inc_id}/steps/0",
                json={"completed": True},
                headers=self.sys_hdr,
            ).status_code,
            200,
        )
        sys_tasks = self.client.get("/api/tasks", headers=self.sys_hdr)
        self.assertEqual(sys_tasks.status_code, 200)
        sys_task_ids = {t["id"] for t in sys_tasks.json()}
        self.assertIn(self.tech_task_id, sys_task_ids)
        self.assertNotIn(self.pdn_task_id, sys_task_ids)
        self.assertEqual(
            self.client.patch(
                f"/api/tasks/{self.tech_task_id}",
                json={"status": "Выполнена", "result": "Закрыто"},
                headers=self.sys_hdr,
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/tasks/{self.pdn_task_id}",
                json={"status": "Выполнена"},
                headers=self.sys_hdr,
            ).status_code,
            403,
        )

        # IB specialist and IT head retain full operational + PDn + RKN confirm capabilities
        for role_name, hdr in (("ib", self.ib_hdr), ("it_head", self.head_hdr)):
            with self.subTest(role=role_name):
                self.assertEqual(self.client.get("/api/incidents/2", headers=hdr).status_code, 200)
                self.assertEqual(self.client.get("/api/incidents/2/rkn", headers=hdr).status_code, 200)
                confirm_resp = self.client.post(
                    f"/api/incidents/{self.pdn2_inc_id}/rkn/confirm",
                    json={"confirmation": f"RKN-{role_name.upper()}"},
                    headers=hdr,
                )
                self.assertEqual(confirm_resp.status_code, 200, confirm_resp.text)
                self.assertEqual(confirm_resp.json()["confirmation"], f"RKN-{role_name.upper()}")

                self.assertEqual(
                    self.client.patch(
                        f"/api/incidents/{self.pdn2_inc_id}",
                        json={"severity": "critical"},
                        headers=hdr,
                    ).status_code,
                    200,
                )
                self.assertEqual(
                    self.client.put(
                        f"/api/incidents/{self.pdn2_inc_id}/steps/0",
                        json={"completed": True},
                        headers=hdr,
                    ).status_code,
                    200,
                )
                self.assertEqual(self.client.get("/api/tasks", headers=hdr).status_code, 200)

        # IT head can complete PDn task and close PDn incident
        self.assertEqual(
            self.client.patch(
                f"/api/tasks/{self.pdn_task_id}",
                json={"status": "Выполнена", "result": "Доступ ограничен"},
                headers=self.head_hdr,
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                f"/api/incidents/{self.pdn2_inc_id}/status",
                json={"status": IncidentStatus.CLOSED.value, "outcome": "Устранен"},
                headers=self.head_hdr,
            ).status_code,
            200,
        )


if __name__ == "__main__":
    unittest.main()
